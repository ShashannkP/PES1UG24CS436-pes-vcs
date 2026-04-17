// tree.c — Tree object serialization and construction

#include "tree.h"
#include "pes.h"
#include "index.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

// Implemented in object.c
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

// ─── PROVIDED ───────────────────────────────────────────────────────────────

uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;

    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1;

        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1;

        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1;

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0';

        ptr = null_byte + 1;

        if (ptr + HASH_SIZE > end) return -1;
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    size_t max_size = tree->count * 296;
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1;
        
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── IMPLEMENTATION ─────────────────────────────────────────────────────────

static int path_has_prefix(const char *path, const char *prefix) {
    size_t n = strlen(prefix);
    return strncmp(path, prefix, n) == 0;
}

static int tree_has_entry(const Tree *tree, const char *name) {
    for (int i = 0; i < tree->count; i++) {
        if (strcmp(tree->entries[i].name, name) == 0) return 1;
    }
    return 0;
}

static int build_tree_for_prefix(const Index *index, const char *prefix, ObjectID *id_out) {
    Tree tree;
    tree.count = 0;

    char dirs[MAX_TREE_ENTRIES][256];
    int dir_count = 0;

    size_t prefix_len = strlen(prefix);

    for (int i = 0; i < index->count; i++) {
        const IndexEntry *ie = &index->entries[i];
        if (!path_has_prefix(ie->path, prefix)) continue;

        const char *rest = ie->path + prefix_len;
        if (*rest == '\0') continue;

        const char *slash = strchr(rest, '/');
        if (!slash) {
            if (tree.count >= MAX_TREE_ENTRIES) return -1;
            if (tree_has_entry(&tree, rest)) continue;

            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = ie->mode;
            te->hash = ie->hash;
            snprintf(te->name, sizeof(te->name), "%s", rest);
            continue;
        }

        size_t dir_len = (size_t)(slash - rest);
        if (dir_len == 0 || dir_len >= sizeof(dirs[0])) return -1;

        char name[256];
        memcpy(name, rest, dir_len);
        name[dir_len] = '\0';

        int seen = 0;
        for (int d = 0; d < dir_count; d++) {
            if (strcmp(dirs[d], name) == 0) {
                seen = 1;
                break;
            }
        }
        if (!seen) {
            if (dir_count >= MAX_TREE_ENTRIES) return -1;
            snprintf(dirs[dir_count++], sizeof(dirs[0]), "%s", name);
        }
    }

    for (int d = 0; d < dir_count; d++) {
        if (tree.count >= MAX_TREE_ENTRIES) return -1;

        char child_prefix[1024];
        snprintf(child_prefix, sizeof(child_prefix), "%s%s/", prefix, dirs[d]);

        ObjectID child_id;
        if (build_tree_for_prefix(index, child_prefix, &child_id) != 0) return -1;

        TreeEntry *te = &tree.entries[tree.count++];
        te->mode = MODE_DIR;
        te->hash = child_id;
        snprintf(te->name, sizeof(te->name), "%s", dirs[d]);
    }

    void *data;
    size_t len;
    if (tree_serialize(&tree, &data, &len) != 0) return -1;

    int rc = object_write(OBJ_TREE, data, len, id_out);
    free(data);
    return rc;
}

int tree_from_index(ObjectID *id_out) {
    Index index;
    if (index_load(&index) != 0) return -1;

    return build_tree_for_prefix(&index, "", id_out);
}
