/*
 * Password Manager v2 (fork) - Flipper Zero
 *
 * Features:
 *  - Multiple named lists (one .txt per list) under apps_data (out of SD root)
 *  - Saved Passwords: pick list -> type entries over USB HID (OK), wrap navigation,
 *    L/R opens quick typing-config
 *  - Edit Passwords: add / edit / delete entries; password step = manual or generated
 *  - Manage Lists: new / delete list
 *  - Config (global, persisted): keyboard layout (.kl), key delay, Enter-at-end,
 *    Tab-between-user/pass, start delay
 *  - Built-in random generator (length + char classes, hardware RNG, passgen symbols)
 *
 * Storage line format (per entry), comma-separated with escaping (\\ and \,):
 *    name,username,password
 *
 * NOTE: typing only works over USB HID.
 */

#include <furi.h>
#include <furi_hal.h>
#include <furi_hal_usb.h>
#include <furi_hal_usb_hid.h>
#include <usb_hid.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/variable_item_list.h>
#include <gui/modules/text_input.h>
#include <gui/modules/dialog_ex.h>
#include <gui/view.h>
#include <storage/storage.h>
#include <input/input.h>
#include <notification/notification.h>
#include <notification/notification_messages.h>
#include <stdlib.h>
#include <string.h>

#define PM_DIR        "/ext/apps_data/password_manager"
#define PM_LISTS_DIR  "/ext/apps_data/password_manager/lists"
#define PM_CONFIG     "/ext/apps_data/password_manager/config.cfg"
#define PM_OLD_FILE   "/ext/passwordManager.txt" /* legacy file to migrate */
#define LAYOUTS_DIR   "/ext/badusb/assets/layouts"

#define MAX_ENTRIES   60
#define FIELD_LEN     64
#define NAME_LEN      48
#define PATH_LEN      128
#define LIST_NAME_LEN 32
#define GEN_MAX_LEN   32
#define GEN_MIN_LEN   4

static const char GEN_LOWER[] = "abcdefghijklmnopqrstuvwxyz";
static const char GEN_UPPER[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char GEN_DIGIT[] = "0123456789";
static const char GEN_SYM[]   = "!#$%^&*.-_"; /* same set as passgen */

/* start-delay options (ms) shown in config */
static const uint32_t START_DELAYS[] = {0, 10, 20, 50, 100, 150, 250, 500, 1000};
#define START_DELAY_COUNT (sizeof(START_DELAYS) / sizeof(START_DELAYS[0]))

static uint8_t start_delay_index(uint32_t v) {
    for(uint8_t i = 0; i < START_DELAY_COUNT; i++)
        if(START_DELAYS[i] == v) return i;
    return 0;
}

typedef struct {
    char name[NAME_LEN];
    char username[FIELD_LEN];
    char password[FIELD_LEN];
} Credential;

typedef struct {
    char layout_path[PATH_LEN]; /* empty = US default */
    uint32_t key_delay;         /* ms between key events */
    uint32_t start_delay;       /* ms before typing begins */
    bool enter_at_end;
    bool tab_between;
} Config;

typedef enum {
    ViewMenu,        /* main menu (submenu) */
    ViewListPick,    /* pick a list (submenu) */
    ViewEntries,     /* entries of a list (custom view) */
    ViewActions,     /* per-entry actions in edit mode (submenu) */
    ViewPwMode,      /* manual or generate (submenu) */
    ViewText,        /* text input */
    ViewGen,         /* generator options (variable item list) */
    ViewConfig,      /* config / quick config (variable item list) */
    ViewLayoutPick,  /* pick .kl layout (submenu) */
    ViewConfirm,     /* dialog confirm */
} ViewId;

/* what the user is in the middle of doing */
typedef enum {
    ModeSaved, /* OK on entry = type it */
    ModeEdit,  /* OK on entry = actions */
} Mode;

typedef enum {
    FieldName,
    FieldUser,
    FieldPass,
    FieldListName,
} EditField;

typedef struct {
    Gui* gui;
    ViewDispatcher* vd;
    Storage* storage;
    NotificationApp* notes;

    Submenu* menu;
    Submenu* list_pick;
    Submenu* actions;
    Submenu* pw_mode;
    Submenu* layout_pick;
    TextInput* text_input;
    VariableItemList* gen;
    VariableItemList* config_list;
    DialogEx* confirm;
    View* entries_view;

    Config config;

    /* current working set */
    Credential creds[MAX_ENTRIES];
    uint32_t cred_count;
    char list_path[PATH_LEN];  /* active list file */
    char list_name[LIST_NAME_LEN];
    Mode mode;

    /* entry list view state */
    uint32_t sel;        /* selected entry index */
    uint32_t top;        /* scroll offset */

    /* editing scratch */
    int edit_index;      /* -1 = adding new, else editing existing */
    Credential scratch;
    EditField field;
    char text_buf[FIELD_LEN];

    /* generator options */
    uint32_t gen_len;
    bool gen_lower, gen_upper, gen_digit, gen_sym;

    /* layout file names cache (for picker indexing) */
    char layout_names[16][32];
    uint32_t layout_count;

    /* confirm action target */
    uint8_t confirm_what; /* 1 = delete entry, 2 = delete list */
    uint32_t config_from; /* view to return to when leaving config */

    /* USB HID state (keep the keyboard mode active while app runs) */
    FuriHalUsbInterface* usb_prev;
    bool hid_active;
} App;

static App* g_app = NULL;

/* ---------------- storage helpers ---------------- */

static void pm_ensure_dirs(App* app) {
    storage_common_mkdir(app->storage, "/ext/apps_data");
    storage_common_mkdir(app->storage, PM_DIR);
    storage_common_mkdir(app->storage, PM_LISTS_DIR);
}

/* append c into buf at *pos if room */
static void buf_put(char* buf, size_t cap, size_t* pos, char c) {
    if(*pos < cap - 1) {
        buf[*pos] = c;
        (*pos)++;
    }
}

/* write one field with escaping of \ and , */
static void write_escaped(FuriString* out, const char* s) {
    for(const char* p = s; *p; p++) {
        if(*p == '\\' || *p == ',') furi_string_push_back(out, '\\');
        furi_string_push_back(out, *p);
    }
}

/* parse a raw line into a Credential, honoring \ escapes */
static void parse_line(const char* line, Credential* c) {
    memset(c, 0, sizeof(Credential));
    char* dst[3] = {c->name, c->username, c->password};
    size_t cap[3] = {NAME_LEN, FIELD_LEN, FIELD_LEN};
    size_t pos[3] = {0, 0, 0};
    int field = 0;
    for(const char* p = line; *p; p++) {
        if(*p == '\\' && *(p + 1)) {
            p++;
            if(field < 3) buf_put(dst[field], cap[field], &pos[field], *p);
        } else if(*p == ',') {
            if(field < 2) field++;
        } else if(*p == '\r' || *p == '\n') {
            /* skip */
        } else {
            if(field < 3) buf_put(dst[field], cap[field], &pos[field], *p);
        }
    }
}

/* load all entries from app->list_path into app->creds */
static void list_load(App* app) {
    app->cred_count = 0;
    File* f = storage_file_alloc(app->storage);
    if(storage_file_open(f, app->list_path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        FuriString* line = furi_string_alloc();
        char ch;
        furi_string_reset(line);
        while(storage_file_read(f, &ch, 1) == 1) {
            if(ch == '\n') {
                if(furi_string_size(line) > 0 && app->cred_count < MAX_ENTRIES) {
                    parse_line(furi_string_get_cstr(line), &app->creds[app->cred_count]);
                    app->cred_count++;
                }
                furi_string_reset(line);
            } else {
                furi_string_push_back(line, ch);
            }
        }
        if(furi_string_size(line) > 0 && app->cred_count < MAX_ENTRIES) {
            parse_line(furi_string_get_cstr(line), &app->creds[app->cred_count]);
            app->cred_count++;
        }
        furi_string_free(line);
        storage_file_close(f);
    }
    storage_file_free(f);
}

/* rewrite the whole list file from app->creds (array is source of truth) */
static void list_save(App* app) {
    File* f = storage_file_alloc(app->storage);
    if(storage_file_open(f, app->list_path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        FuriString* line = furi_string_alloc();
        for(uint32_t i = 0; i < app->cred_count; i++) {
            furi_string_reset(line);
            write_escaped(line, app->creds[i].name);
            furi_string_push_back(line, ',');
            write_escaped(line, app->creds[i].username);
            furi_string_push_back(line, ',');
            write_escaped(line, app->creds[i].password);
            furi_string_push_back(line, '\n');
            storage_file_write(f, furi_string_get_cstr(line), furi_string_size(line));
        }
        furi_string_free(line);
        storage_file_close(f);
    }
    storage_file_free(f);
}

static void config_load(App* app) {
    /* defaults */
    app->config.layout_path[0] = '\0';
    app->config.key_delay = 10;
    app->config.start_delay = 0;
    app->config.enter_at_end = true;
    app->config.tab_between = true;

    File* f = storage_file_alloc(app->storage);
    if(storage_file_open(f, PM_CONFIG, FSAM_READ, FSOM_OPEN_EXISTING)) {
        FuriString* line = furi_string_alloc();
        char ch;
        furi_string_reset(line);
        do {
            int n = storage_file_read(f, &ch, 1);
            if(n == 1 && ch != '\n') {
                furi_string_push_back(line, ch);
                continue;
            }
            const char* s = furi_string_get_cstr(line);
            if(strncmp(s, "layout=", 7) == 0) {
                strncpy(app->config.layout_path, s + 7, PATH_LEN - 1);
            } else if(strncmp(s, "key_delay=", 10) == 0) {
                app->config.key_delay = (uint32_t)atoi(s + 10);
            } else if(strncmp(s, "start_delay=", 12) == 0) {
                app->config.start_delay = (uint32_t)atoi(s + 12);
            } else if(strncmp(s, "enter=", 6) == 0) {
                app->config.enter_at_end = atoi(s + 6) != 0;
            } else if(strncmp(s, "tab=", 4) == 0) {
                app->config.tab_between = atoi(s + 4) != 0;
            }
            furi_string_reset(line);
            if(n != 1) break;
        } while(true);
        furi_string_free(line);
        storage_file_close(f);
    }
    storage_file_free(f);
}

static void config_save(App* app) {
    File* f = storage_file_alloc(app->storage);
    if(storage_file_open(f, PM_CONFIG, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        FuriString* s = furi_string_alloc();
        furi_string_printf(
            s,
            "layout=%s\nkey_delay=%lu\nstart_delay=%lu\nenter=%d\ntab=%d\n",
            app->config.layout_path,
            (unsigned long)app->config.key_delay,
            (unsigned long)app->config.start_delay,
            app->config.enter_at_end ? 1 : 0,
            app->config.tab_between ? 1 : 0);
        storage_file_write(f, furi_string_get_cstr(s), furi_string_size(s));
        furi_string_free(s);
        storage_file_close(f);
    }
    storage_file_free(f);
}

/* one-time migration of legacy root file into a "default" list */
static void migrate_legacy(App* app) {
    FileInfo fi;
    if(storage_common_stat(app->storage, PM_OLD_FILE, &fi) != FSE_OK) return;
    char dest[PATH_LEN];
    snprintf(dest, PATH_LEN, "%s/default.txt", PM_LISTS_DIR);
    if(storage_common_stat(app->storage, dest, &fi) == FSE_OK) return; /* already migrated */
    storage_common_copy(app->storage, PM_OLD_FILE, dest);
}

/* ---------------- USB HID typing ---------------- */

static uint16_t layout_table[128];
static bool layout_loaded = false;

static void load_layout(App* app) {
    layout_loaded = false;
    if(app->config.layout_path[0] == '\0') return; /* US default via macro */
    File* f = storage_file_alloc(app->storage);
    if(storage_file_open(f, app->config.layout_path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        uint16_t buf[128];
        uint16_t got = storage_file_read(f, buf, sizeof(buf));
        if(got == sizeof(buf)) {
            memcpy(layout_table, buf, sizeof(buf));
            layout_loaded = true;
        }
        storage_file_close(f);
    }
    storage_file_free(f);
}

static uint16_t key_for_char(char c) {
    /* Uppercase letters: build from the (known-good) lowercase key plus an
       explicit shift bit. This avoids depending on the layout file's uppercase
       / modifier encoding, which differs between firmwares and was making
       uppercase come out lowercase. */
    if(c >= 'A' && c <= 'Z') {
        char lower = (char)(c - 'A' + 'a');
        uint16_t base = layout_loaded ? layout_table[(uint8_t)lower] : HID_ASCII_TO_KEY(lower);
        return (uint16_t)(base | KEY_MOD_LEFT_SHIFT);
    }
    uint8_t idx = (uint8_t)c;
    if(layout_loaded && idx < 128) return layout_table[idx];
    return HID_ASCII_TO_KEY(c);
}

static void type_one(uint16_t k, uint32_t d) {
    if(!k) return;
    furi_hal_hid_kb_press(k);
    furi_delay_ms(d);
    furi_hal_hid_kb_release(k);
    furi_delay_ms(d);
}

static void type_str(const char* s, uint32_t d) {
    for(const char* p = s; *p; p++) type_one(key_for_char(*p), d);
}

static void type_credential(App* app, const Credential* cr) {
    /* Switch to keyboard mode once and stay there while the app runs. Only the
       first type waits for the host to enumerate; later ones are instant and
       race-free, which fixes both dropped opening characters and the
       "types from the middle" problem on repeat attempts. */
    if(!app->hid_active) {
        app->usb_prev = furi_hal_usb_get_config();
        furi_hal_usb_unlock();
        if(!furi_hal_usb_set_config(&usb_hid, NULL)) return;
        uint32_t waited = 0;
        while(!furi_hal_hid_is_connected() && waited < 2000) {
            furi_delay_ms(20);
            waited += 20;
        }
        furi_delay_ms(150); /* settle after the host reports ready */
        app->hid_active = true;
    }

    if(app->config.start_delay) furi_delay_ms(app->config.start_delay);

    uint32_t d = app->config.key_delay < 5 ? 5 : app->config.key_delay;

    if(cr->username[0]) {
        type_str(cr->username, d);
        if(app->config.tab_between) type_one(HID_KEYBOARD_TAB, d);
    }
    type_str(cr->password, d);
    if(app->config.enter_at_end) type_one(HID_KEYBOARD_RETURN, d);

    furi_hal_hid_kb_release_all();
}

/* ---------------- generator ---------------- */

static uint32_t rng_below(uint32_t n) {
    if(n == 0) return 0;
    uint32_t limit = UINT32_MAX - (UINT32_MAX % n);
    uint32_t r;
    do {
        r = furi_hal_random_get();
    } while(r >= limit);
    return r % n;
}

static void generate_password(App* app, char* out, size_t cap) {
    char pool[96];
    size_t pn = 0;
    if(app->gen_lower) { memcpy(pool + pn, GEN_LOWER, 26); pn += 26; }
    if(app->gen_upper) { memcpy(pool + pn, GEN_UPPER, 26); pn += 26; }
    if(app->gen_digit) { memcpy(pool + pn, GEN_DIGIT, 10); pn += 10; }
    if(app->gen_sym)   { memcpy(pool + pn, GEN_SYM, strlen(GEN_SYM)); pn += strlen(GEN_SYM); }
    if(pn == 0) { memcpy(pool, GEN_LOWER, 26); pn = 26; } /* never empty */

    uint32_t len = app->gen_len;
    if(len >= cap) len = cap - 1;
    for(uint32_t i = 0; i < len; i++) {
        out[i] = pool[rng_below(pn)];
    }
    out[len] = '\0';
}

/* ---------------- forward decls ---------------- */
static void show_menu(App* app);
static void show_list_pick(App* app);
static void show_entries(App* app);
static void show_actions(App* app);
static void show_pw_mode(App* app);
static void show_text(App* app, EditField field, const char* preset);
static void show_gen(App* app);
static void show_layout_pick(App* app);
static void rebuild_config_list(App* app);

/* ---------------- main menu ---------------- */
enum { MenuSaved, MenuEdit, MenuLists, MenuConfig };

static void menu_cb(void* ctx, uint32_t index) {
    App* app = ctx;
    if(index == MenuSaved) {
        app->mode = ModeSaved;
        show_list_pick(app);
    } else if(index == MenuEdit) {
        app->mode = ModeEdit;
        show_list_pick(app);
    } else if(index == MenuLists) {
        app->mode = ModeEdit; /* manage-lists reuses list pick + new/delete */
        show_list_pick(app); /* list pick has "New list" in edit/manage */
    } else if(index == MenuConfig) {
        app->config_from = ViewMenu;
        rebuild_config_list(app);
        view_dispatcher_switch_to_view(app->vd, ViewConfig);
    }
}

static void show_menu(App* app) {
    submenu_reset(app->menu);
    submenu_set_header(app->menu, "Password Manager");
    submenu_add_item(app->menu, "Saved Passwords", MenuSaved, menu_cb, app);
    submenu_add_item(app->menu, "Edit Passwords", MenuEdit, menu_cb, app);
    submenu_add_item(app->menu, "Manage Lists", MenuLists, menu_cb, app);
    submenu_add_item(app->menu, "Config", MenuConfig, menu_cb, app);
    view_dispatcher_switch_to_view(app->vd, ViewMenu);
}

/* ---------------- list picker ---------------- */

#define LISTPICK_NEW 0xFFFE

static void listpick_cb(void* ctx, uint32_t index) {
    App* app = ctx;
    if(index == LISTPICK_NEW) {
        /* create a new list: ask for a name */
        app->edit_index = -2; /* signal: creating list */
        show_text(app, FieldListName, "");
        return;
    }
    /* index is an offset into the lists dir; resolve name stored in submenu label */
    /* we instead stored the filename via a parallel approach: re-scan to map index */
    /* Simpler: index encodes selection; rebuild path from stored name list. */
    /* Here we kept names in layout_names? No - use a fresh scan keyed by index. */
    /* Resolve by scanning dir again and matching the Nth .txt */
    File* dir = storage_file_alloc(app->storage);
    uint32_t i = 0;
    char found[LIST_NAME_LEN] = {0};
    if(storage_dir_open(dir, PM_LISTS_DIR)) {
        FileInfo info;
        char namebuf[LIST_NAME_LEN];
        while(storage_dir_read(dir, &info, namebuf, sizeof(namebuf))) {
            if(info.flags & FSF_DIRECTORY) continue;
            size_t l = strlen(namebuf);
            if(l < 5 || strcmp(namebuf + l - 4, ".txt") != 0) continue;
            if(i == index) {
                strncpy(found, namebuf, LIST_NAME_LEN - 1);
                break;
            }
            i++;
        }
        storage_dir_close(dir);
    }
    storage_file_free(dir);
    if(found[0] == '\0') return;

    snprintf(app->list_path, PATH_LEN, "%s/%s", PM_LISTS_DIR, found);
    strncpy(app->list_name, found, LIST_NAME_LEN - 1);
    list_load(app);
    app->sel = 0;
    app->top = 0;
    show_entries(app);
}

static void show_list_pick(App* app) {
    submenu_reset(app->list_pick);
    submenu_set_header(app->list_pick, app->mode == ModeSaved ? "Pick list (type)" : "Pick list");
    File* dir = storage_file_alloc(app->storage);
    uint32_t i = 0;
    if(storage_dir_open(dir, PM_LISTS_DIR)) {
        FileInfo info;
        char namebuf[LIST_NAME_LEN];
        while(storage_dir_read(dir, &info, namebuf, sizeof(namebuf))) {
            if(info.flags & FSF_DIRECTORY) continue;
            size_t l = strlen(namebuf);
            if(l < 5 || strcmp(namebuf + l - 4, ".txt") != 0) continue;
            submenu_add_item(app->list_pick, namebuf, i, listpick_cb, app);
            i++;
        }
        storage_dir_close(dir);
    }
    storage_file_free(dir);
    if(app->mode != ModeSaved) {
        submenu_add_item(app->list_pick, "[+ New list]", LISTPICK_NEW, listpick_cb, app);
    }
    view_dispatcher_switch_to_view(app->vd, ViewListPick);
}

/* ---------------- entries custom view ---------------- */

typedef struct {
    App* app;
} EntriesModel;

static void entries_draw(Canvas* canvas, void* model) {
    EntriesModel* m = model;
    App* app = m->app;
    canvas_clear(canvas);
    canvas_set_font(canvas, FontSecondary);

    /* header */
    canvas_draw_str(canvas, 2, 10, app->list_name);
    canvas_draw_line(canvas, 0, 12, 128, 12);

    const uint32_t rows = 3; /* leave room for the bottom hint bar */
    if(app->cred_count == 0) {
        canvas_draw_str(canvas, 2, 30, "(empty)");
        if(app->mode == ModeEdit) canvas_draw_str(canvas, 2, 44, "OK: add entry");
    } else {
        if(app->sel < app->top) app->top = app->sel;
        if(app->sel >= app->top + rows) app->top = app->sel - rows + 1;
        for(uint32_t r = 0; r < rows; r++) {
            uint32_t idx = app->top + r;
            if(idx >= app->cred_count) break;
            uint32_t y = 24 + r * 11;
            if(idx == app->sel) {
                canvas_draw_box(canvas, 0, y - 9, 128, 11);
                canvas_set_color(canvas, ColorWhite);
            }
            canvas_draw_str(canvas, 3, y, app->creds[idx].name);
            canvas_set_color(canvas, ColorBlack);
        }
    }

    /* bottom-right "config >" hint (Saved mode only - that's where L/R works) */
    if(app->mode == ModeSaved) {
        const char* label = "config";
        uint16_t tw = canvas_string_width(canvas, label);
        uint8_t boxw = tw + 14;
        uint8_t boxh = 11;
        uint8_t bx = 128 - boxw;
        uint8_t by = 64 - boxh;
        canvas_draw_box(canvas, bx, by, boxw, boxh);
        canvas_set_color(canvas, ColorWhite);
        canvas_draw_str(canvas, bx + 3, by + 8, label);
        /* right-pointing arrow, apex points right */
        uint8_t ax = bx + 3 + tw + 5;
        canvas_draw_triangle(canvas, ax, by + boxh / 2, 5, 4, CanvasDirectionLeftToRight);
        canvas_set_color(canvas, ColorBlack);
    }
}

static bool entries_input(InputEvent* event, void* ctx) {
    App* app = ctx;
    if(event->type != InputTypeShort && event->type != InputTypeRepeat) return false;
    {
        switch(event->key) {
        case InputKeyUp:
            if(app->cred_count == 0) return true;
            if(app->sel == 0)
                app->sel = app->cred_count - 1;
            else
                app->sel--;
            with_view_model(
                app->entries_view, EntriesModel * m, { m->app = app; }, true);
            return true;
        case InputKeyDown:
            if(app->cred_count == 0) return true;
            if(app->sel + 1 >= app->cred_count)
                app->sel = 0;
            else
                app->sel++;
            with_view_model(
                app->entries_view, EntriesModel * m, { m->app = app; }, true);
            return true;
        case InputKeyLeft:
        case InputKeyRight:
            if(app->mode == ModeSaved) {
                app->config_from = ViewEntries;
                rebuild_config_list(app);
                view_dispatcher_switch_to_view(app->vd, ViewConfig);
            }
            return true;
        case InputKeyOk:
            if(app->mode == ModeSaved) {
                if(app->cred_count > 0) {
                    notification_message(app->notes, &sequence_blink_blue_100);
                    type_credential(app, &app->creds[app->sel]);
                }
            } else {
                /* edit mode: OK opens actions (or add if empty) */
                show_actions(app);
            }
            return true;
        case InputKeyBack:
            show_list_pick(app);
            return true;
        default:
            return false;
        }
    }
    return false;
}

static void show_entries(App* app) {
    with_view_model(app->entries_view, EntriesModel * m, { m->app = app; }, true);
    view_dispatcher_switch_to_view(app->vd, ViewEntries);
}

/* ---------------- per-entry actions (edit mode) ---------------- */
enum { ActAdd, ActEdit, ActDelete, ActDeleteList };

static void actions_cb(void* ctx, uint32_t index) {
    App* app = ctx;
    if(index == ActAdd) {
        app->edit_index = -1;
        memset(&app->scratch, 0, sizeof(Credential));
        show_text(app, FieldName, "");
    } else if(index == ActEdit) {
        if(app->cred_count == 0) return;
        app->edit_index = (int)app->sel;
        app->scratch = app->creds[app->sel];
        show_text(app, FieldName, app->scratch.name);
    } else if(index == ActDelete) {
        if(app->cred_count == 0) return;
        app->confirm_what = 1;
        dialog_ex_set_header(app->confirm, "Delete entry?", 64, 10, AlignCenter, AlignCenter);
        dialog_ex_set_text(
            app->confirm, app->creds[app->sel].name, 64, 32, AlignCenter, AlignCenter);
        dialog_ex_set_left_button_text(app->confirm, "Cancel");
        dialog_ex_set_right_button_text(app->confirm, "Delete");
        view_dispatcher_switch_to_view(app->vd, ViewConfirm);
    } else if(index == ActDeleteList) {
        app->confirm_what = 2;
        dialog_ex_set_header(app->confirm, "Delete LIST?", 64, 10, AlignCenter, AlignCenter);
        dialog_ex_set_text(app->confirm, app->list_name, 64, 32, AlignCenter, AlignCenter);
        dialog_ex_set_left_button_text(app->confirm, "Cancel");
        dialog_ex_set_right_button_text(app->confirm, "Delete");
        view_dispatcher_switch_to_view(app->vd, ViewConfirm);
    }
}

static void show_actions(App* app) {
    submenu_reset(app->actions);
    submenu_set_header(app->actions, "Entry actions");
    submenu_add_item(app->actions, "Add entry", ActAdd, actions_cb, app);
    if(app->cred_count > 0) {
        submenu_add_item(app->actions, "Edit selected", ActEdit, actions_cb, app);
        submenu_add_item(app->actions, "Delete selected", ActDelete, actions_cb, app);
    }
    submenu_add_item(app->actions, "Delete this list", ActDeleteList, actions_cb, app);
    view_dispatcher_switch_to_view(app->vd, ViewActions);
}

/* ---------------- confirm dialog ---------------- */
static void confirm_cb(DialogExResult result, void* ctx) {
    App* app = ctx;
    if(result == DialogExResultRight) {
        if(app->confirm_what == 1) {
            /* delete entry: shift array */
            for(uint32_t i = app->sel; i + 1 < app->cred_count; i++)
                app->creds[i] = app->creds[i + 1];
            if(app->cred_count > 0) app->cred_count--;
            if(app->sel >= app->cred_count && app->sel > 0) app->sel--;
            list_save(app);
            show_entries(app);
        } else if(app->confirm_what == 2) {
            storage_common_remove(app->storage, app->list_path);
            show_list_pick(app);
        }
    } else {
        if(app->confirm_what == 1)
            show_actions(app);
        else
            show_entries(app);
    }
}

/* ---------------- password mode (manual / generate) ---------------- */
enum { PwManual, PwGenerate };

static void pwmode_cb(void* ctx, uint32_t index) {
    App* app = ctx;
    if(index == PwManual) {
        show_text(app, FieldPass, app->scratch.password);
    } else {
        show_gen(app);
    }
}

static void show_pw_mode(App* app) {
    submenu_reset(app->pw_mode);
    submenu_set_header(app->pw_mode, "Password");
    submenu_add_item(app->pw_mode, "Enter manually", PwManual, pwmode_cb, app);
    submenu_add_item(app->pw_mode, "Generate random", PwGenerate, pwmode_cb, app);
    view_dispatcher_switch_to_view(app->vd, ViewPwMode);
}

/* ---------------- text input ---------------- */
static void text_done_cb(void* ctx) {
    App* app = ctx;
    if(app->field == FieldListName) {
        /* create new list file */
        if(app->text_buf[0]) {
            snprintf(app->list_path, PATH_LEN, "%s/%s.txt", PM_LISTS_DIR, app->text_buf);
            strncpy(app->list_name, app->text_buf, LIST_NAME_LEN - 1);
            app->cred_count = 0;
            list_save(app); /* create empty file */
            show_entries(app);
        } else {
            show_list_pick(app);
        }
        return;
    }
    if(app->field == FieldName) {
        strncpy(app->scratch.name, app->text_buf, NAME_LEN - 1);
        show_text(app, FieldUser, app->scratch.username);
    } else if(app->field == FieldUser) {
        strncpy(app->scratch.username, app->text_buf, FIELD_LEN - 1);
        show_pw_mode(app);
    } else if(app->field == FieldPass) {
        strncpy(app->scratch.password, app->text_buf, FIELD_LEN - 1);
        /* commit scratch into array */
        if(app->edit_index >= 0 && (uint32_t)app->edit_index < app->cred_count) {
            app->creds[app->edit_index] = app->scratch;
        } else if(app->cred_count < MAX_ENTRIES) {
            app->creds[app->cred_count++] = app->scratch;
        }
        list_save(app);
        show_entries(app);
    }
}

static void show_text(App* app, EditField field, const char* preset) {
    app->field = field;
    memset(app->text_buf, 0, sizeof(app->text_buf));
    if(preset) strncpy(app->text_buf, preset, sizeof(app->text_buf) - 1);
    const char* hdr = "Enter text";
    if(field == FieldName) hdr = "Name / site";
    else if(field == FieldUser) hdr = "Username";
    else if(field == FieldPass) hdr = "Password";
    else if(field == FieldListName) hdr = "New list name";
    text_input_reset(app->text_input);
    text_input_set_header_text(app->text_input, hdr);
    /* username/password may be left blank; name and list name are required */
    size_t minlen = (field == FieldName || field == FieldListName) ? 1 : 0;
    text_input_set_minimum_length(app->text_input, minlen);
    text_input_set_result_callback(
        app->text_input, text_done_cb, app, app->text_buf, sizeof(app->text_buf), false);
    view_dispatcher_switch_to_view(app->vd, ViewText);
}

/* ---------------- generator options ---------------- */
static void gen_len_cb(VariableItem* item) {
    App* app = variable_item_get_context(item);
    app->gen_len = GEN_MIN_LEN + variable_item_get_current_value_index(item);
    char b[8];
    snprintf(b, sizeof(b), "%lu", (unsigned long)app->gen_len);
    variable_item_set_current_value_text(item, b);
}
static void gen_lower_cb(VariableItem* item) {
    App* app = variable_item_get_context(item);
    app->gen_lower = variable_item_get_current_value_index(item);
    variable_item_set_current_value_text(item, app->gen_lower ? "On" : "Off");
}
static void gen_upper_cb(VariableItem* item) {
    App* app = variable_item_get_context(item);
    app->gen_upper = variable_item_get_current_value_index(item);
    variable_item_set_current_value_text(item, app->gen_upper ? "On" : "Off");
}
static void gen_digit_cb(VariableItem* item) {
    App* app = variable_item_get_context(item);
    app->gen_digit = variable_item_get_current_value_index(item);
    variable_item_set_current_value_text(item, app->gen_digit ? "On" : "Off");
}
static void gen_sym_cb(VariableItem* item) {
    App* app = variable_item_get_context(item);
    app->gen_sym = variable_item_get_current_value_index(item);
    variable_item_set_current_value_text(item, app->gen_sym ? "On" : "Off");
}

/* OK on the generator list = generate + accept into scratch.password */
static void gen_enter_cb(void* ctx, uint32_t index) {
    UNUSED(index);
    App* app = ctx;
    generate_password(app, app->scratch.password, FIELD_LEN);
    notification_message(app->notes, &sequence_blink_green_100);
    /* commit (same path as manual password done) */
    if(app->edit_index >= 0 && (uint32_t)app->edit_index < app->cred_count) {
        app->creds[app->edit_index] = app->scratch;
    } else if(app->cred_count < MAX_ENTRIES) {
        app->creds[app->cred_count++] = app->scratch;
    }
    list_save(app);
    show_entries(app);
}

static void add_toggle(
    VariableItemList* l, const char* label, bool val, VariableItemChangeCallback cb, App* app) {
    VariableItem* it = variable_item_list_add(l, label, 2, cb, app);
    variable_item_set_current_value_index(it, val ? 1 : 0);
    variable_item_set_current_value_text(it, val ? "On" : "Off");
}

static void show_gen(App* app) {
    variable_item_list_reset(app->gen);
    VariableItem* it = variable_item_list_add(
        app->gen, "Length", GEN_MAX_LEN - GEN_MIN_LEN + 1, gen_len_cb, app);
    variable_item_set_current_value_index(it, app->gen_len - GEN_MIN_LEN);
    char b[8];
    snprintf(b, sizeof(b), "%lu", (unsigned long)app->gen_len);
    variable_item_set_current_value_text(it, b);
    add_toggle(app->gen, "Lowercase", app->gen_lower, gen_lower_cb, app);
    add_toggle(app->gen, "Uppercase", app->gen_upper, gen_upper_cb, app);
    add_toggle(app->gen, "Digits", app->gen_digit, gen_digit_cb, app);
    add_toggle(app->gen, "Symbols", app->gen_sym, gen_sym_cb, app);
    variable_item_list_add(app->gen, ">> Generate <<", 0, NULL, NULL);
    variable_item_list_set_enter_callback(app->gen, gen_enter_cb, app);
    view_dispatcher_switch_to_view(app->vd, ViewGen);
}

/* ---------------- config / quick config ---------------- */
static void config_enter_cb(void* ctx, uint32_t index) {
    App* app = ctx;
    if(index == 0) show_layout_pick(app); /* OK on the Layout row */
}
static void cfg_delay_cb(VariableItem* item) {
    App* app = variable_item_get_context(item);
    app->config.key_delay = variable_item_get_current_value_index(item) * 5; /* 0..50 */
    char b[8];
    snprintf(b, sizeof(b), "%lums", (unsigned long)app->config.key_delay);
    variable_item_set_current_value_text(item, b);
    config_save(app);
}
static void cfg_start_cb(VariableItem* item) {
    App* app = variable_item_get_context(item);
    app->config.start_delay = START_DELAYS[variable_item_get_current_value_index(item)];
    char b[10];
    snprintf(b, sizeof(b), "%lums", (unsigned long)app->config.start_delay);
    variable_item_set_current_value_text(item, b);
    config_save(app);
}
static void cfg_enter_cb(VariableItem* item) {
    App* app = variable_item_get_context(item);
    app->config.enter_at_end = variable_item_get_current_value_index(item);
    variable_item_set_current_value_text(item, app->config.enter_at_end ? "On" : "Off");
    config_save(app);
}
static void cfg_tab_cb(VariableItem* item) {
    App* app = variable_item_get_context(item);
    app->config.tab_between = variable_item_get_current_value_index(item);
    variable_item_set_current_value_text(item, app->config.tab_between ? "On" : "Off");
    config_save(app);
}

static const char* layout_label(App* app) {
    if(app->config.layout_path[0] == '\0') return "US (default)";
    const char* s = strrchr(app->config.layout_path, '/');
    return s ? s + 1 : app->config.layout_path;
}

static void rebuild_config_list(App* app) {
    variable_item_list_reset(app->config_list);
    VariableItem* it;

    it = variable_item_list_add(app->config_list, "Layout (OK)", 1, NULL, app);
    variable_item_set_current_value_text(it, layout_label(app));

    it = variable_item_list_add(app->config_list, "Key delay", 11, cfg_delay_cb, app);
    variable_item_set_current_value_index(it, app->config.key_delay / 5);
    char b[10];
    snprintf(b, sizeof(b), "%lums", (unsigned long)app->config.key_delay);
    variable_item_set_current_value_text(it, b);

    it = variable_item_list_add(
        app->config_list, "Start delay", START_DELAY_COUNT, cfg_start_cb, app);
    variable_item_set_current_value_index(it, start_delay_index(app->config.start_delay));
    snprintf(b, sizeof(b), "%lums", (unsigned long)app->config.start_delay);
    variable_item_set_current_value_text(it, b);

    add_toggle(app->config_list, "Enter at end", app->config.enter_at_end, cfg_enter_cb, app);
    add_toggle(app->config_list, "Tab between", app->config.tab_between, cfg_tab_cb, app);

    /* OK on the "Layout" row opens the picker */
    variable_item_list_set_enter_callback(app->config_list, config_enter_cb, app);
}

/* ---------------- layout picker ---------------- */
#define LAYOUT_US 0xFFFD

static void layout_cb(void* ctx, uint32_t index) {
    App* app = ctx;
    if(index == LAYOUT_US) {
        app->config.layout_path[0] = '\0';
    } else if(index < app->layout_count) {
        snprintf(
            app->config.layout_path, PATH_LEN, "%s/%s", LAYOUTS_DIR, app->layout_names[index]);
    }
    config_save(app);
    load_layout(app);
    rebuild_config_list(app);
    view_dispatcher_switch_to_view(app->vd, ViewConfig);
}

static void show_layout_pick(App* app) {
    submenu_reset(app->layout_pick);
    submenu_set_header(app->layout_pick, "Keyboard layout");
    submenu_add_item(app->layout_pick, "US (default)", LAYOUT_US, layout_cb, app);
    app->layout_count = 0;
    File* dir = storage_file_alloc(app->storage);
    if(storage_dir_open(dir, LAYOUTS_DIR)) {
        FileInfo info;
        char namebuf[32];
        while(storage_dir_read(dir, &info, namebuf, sizeof(namebuf)) &&
              app->layout_count < 16) {
            if(info.flags & FSF_DIRECTORY) continue;
            size_t l = strlen(namebuf);
            if(l < 4 || strcmp(namebuf + l - 3, ".kl") != 0) continue;
            strncpy(app->layout_names[app->layout_count], namebuf, 31);
            submenu_add_item(
                app->layout_pick, namebuf, app->layout_count, layout_cb, app);
            app->layout_count++;
        }
        storage_dir_close(dir);
    }
    storage_file_free(dir);
    view_dispatcher_switch_to_view(app->vd, ViewLayoutPick);
}

/* ---------------- navigation (Back) ---------------- */
static uint32_t nav_to_menu(void* ctx) {
    UNUSED(ctx);
    return ViewMenu;
}
static uint32_t nav_exit(void* ctx) {
    UNUSED(ctx);
    return VIEW_NONE;
}
static uint32_t nav_to_entries(void* ctx) {
    UNUSED(ctx);
    return ViewEntries;
}
static uint32_t nav_to_config(void* ctx) {
    UNUSED(ctx);
    return ViewConfig;
}
static uint32_t nav_to_pwmode(void* ctx) {
    UNUSED(ctx);
    return ViewPwMode;
}
static uint32_t nav_config_back(void* ctx) {
    UNUSED(ctx);
    return g_app ? g_app->config_from : ViewMenu;
}

/* ---------------- alloc / free / run ---------------- */
static App* app_alloc(void) {
    App* app = malloc(sizeof(App));
    memset(app, 0, sizeof(App));
    g_app = app;

    app->gui = furi_record_open(RECORD_GUI);
    app->storage = furi_record_open(RECORD_STORAGE);
    app->notes = furi_record_open(RECORD_NOTIFICATION);

    app->gen_len = 16;
    app->gen_lower = app->gen_upper = app->gen_digit = true;
    app->gen_sym = true;
    app->edit_index = -1;

    pm_ensure_dirs(app);
    config_load(app);
    load_layout(app);
    migrate_legacy(app);

    app->vd = view_dispatcher_alloc();
    view_dispatcher_attach_to_gui(app->vd, app->gui, ViewDispatcherTypeFullscreen);

    app->menu = submenu_alloc();
    view_set_previous_callback(submenu_get_view(app->menu), nav_exit);
    view_dispatcher_add_view(app->vd, ViewMenu, submenu_get_view(app->menu));

    app->list_pick = submenu_alloc();
    view_set_previous_callback(submenu_get_view(app->list_pick), nav_to_menu);
    view_dispatcher_add_view(app->vd, ViewListPick, submenu_get_view(app->list_pick));

    app->actions = submenu_alloc();
    view_set_previous_callback(submenu_get_view(app->actions), nav_to_entries);
    view_dispatcher_add_view(app->vd, ViewActions, submenu_get_view(app->actions));

    app->pw_mode = submenu_alloc();
    view_set_previous_callback(submenu_get_view(app->pw_mode), nav_to_entries);
    view_dispatcher_add_view(app->vd, ViewPwMode, submenu_get_view(app->pw_mode));

    app->layout_pick = submenu_alloc();
    view_set_previous_callback(submenu_get_view(app->layout_pick), nav_to_config);
    view_dispatcher_add_view(app->vd, ViewLayoutPick, submenu_get_view(app->layout_pick));

    app->text_input = text_input_alloc();
    view_set_previous_callback(text_input_get_view(app->text_input), nav_to_entries);
    view_dispatcher_add_view(app->vd, ViewText, text_input_get_view(app->text_input));

    app->gen = variable_item_list_alloc();
    view_set_previous_callback(variable_item_list_get_view(app->gen), nav_to_pwmode);
    view_dispatcher_add_view(app->vd, ViewGen, variable_item_list_get_view(app->gen));

    app->config_list = variable_item_list_alloc();
    view_set_previous_callback(variable_item_list_get_view(app->config_list), nav_config_back);
    view_dispatcher_add_view(app->vd, ViewConfig, variable_item_list_get_view(app->config_list));

    app->confirm = dialog_ex_alloc();
    dialog_ex_set_context(app->confirm, app);
    dialog_ex_set_result_callback(app->confirm, confirm_cb);
    view_dispatcher_add_view(app->vd, ViewConfirm, dialog_ex_get_view(app->confirm));

    app->entries_view = view_alloc();
    view_allocate_model(app->entries_view, ViewModelTypeLocking, sizeof(EntriesModel));
    view_set_context(app->entries_view, app);
    view_set_draw_callback(app->entries_view, entries_draw);
    view_set_input_callback(app->entries_view, entries_input);
    view_dispatcher_add_view(app->vd, ViewEntries, app->entries_view);

    return app;
}

static void app_free(App* app) {
    /* restore USB mode if we switched to keyboard */
    if(app->hid_active) {
        furi_hal_hid_kb_release_all();
        furi_hal_usb_set_config(app->usb_prev, NULL);
    }
    view_dispatcher_remove_view(app->vd, ViewMenu);
    view_dispatcher_remove_view(app->vd, ViewListPick);
    view_dispatcher_remove_view(app->vd, ViewActions);
    view_dispatcher_remove_view(app->vd, ViewPwMode);
    view_dispatcher_remove_view(app->vd, ViewLayoutPick);
    view_dispatcher_remove_view(app->vd, ViewText);
    view_dispatcher_remove_view(app->vd, ViewGen);
    view_dispatcher_remove_view(app->vd, ViewConfig);
    view_dispatcher_remove_view(app->vd, ViewConfirm);
    view_dispatcher_remove_view(app->vd, ViewEntries);

    submenu_free(app->menu);
    submenu_free(app->list_pick);
    submenu_free(app->actions);
    submenu_free(app->pw_mode);
    submenu_free(app->layout_pick);
    text_input_free(app->text_input);
    variable_item_list_free(app->gen);
    variable_item_list_free(app->config_list);
    dialog_ex_free(app->confirm);
    view_free(app->entries_view);
    view_dispatcher_free(app->vd);

    furi_record_close(RECORD_NOTIFICATION);
    furi_record_close(RECORD_STORAGE);
    furi_record_close(RECORD_GUI);
    free(app);
}

int32_t password_manager_app(void* p) {
    UNUSED(p);
    App* app = app_alloc();
    show_menu(app);
    view_dispatcher_run(app->vd);
    app_free(app);
    return 0;
}
