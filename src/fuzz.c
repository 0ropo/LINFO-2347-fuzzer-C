#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/stat.h>
#include <limits.h>
#include <time.h>
#include <stdlib.h>

#include "utils.h"
#include "fuzz.h"

/**
 * Run the extractor on generated archive and check if it crashes.
 * On crash, save the failing archive under success_<field>_<value>_<file>.
 */
void run_fuzz(int argc, char* argv[], struct tar_t* archive, const char* success_name) {
    generate_archive(archive, "archive.tar");

    int result = validate_fuzzing(argc, argv);

    if (result == 1) {
        printf("[OK] Crash detected!\n");
        generate_archive(archive, success_name);
        printf("Saved crashing archive as: %s\n", success_name);
    } 
    else if (result == 0) {
        printf("[KO] No crash.\n");
    } 
    else {
        printf("[ERR] validate_fuzzing failed.\n");
    }
}

/**
 * Fuzz typeflag values [0..255] and save successful crash archives.
 */
void fuzz_typeflag(int argc, char* argv[]) {
    const char* tested_file = get_filename(argv[1]);

    for (int value = 0; value <= 255; value++) {
        struct tar_t archive;
        char success_name[128];

        init_clean_archive(&archive);
        archive.typeflag = (char)value;

        snprintf(success_name, sizeof(success_name), "success_typeflag_%02X_%s.tar", value, tested_file);

        printf("\n--- Testing typeflag = 0x%02X", value);

        if (value >= 32 && value <= 126) {
            printf(" ('%c')", value);
        }

        run_fuzz(argc, argv, &archive, success_name);
    }
}

/**
 * Fuzz non-null termination of each header field by filling bytes with 'A'.
 */
void fuzz_non_null_termination(int argc, char* argv[]) {
    struct tar_t archive;
    const char* tested_file = get_filename(argv[1]);

    field_desc fields[] = {
        {"name",     offsetof(struct tar_t, name),     sizeof(archive.name)},
        {"mode",     offsetof(struct tar_t, mode),     sizeof(archive.mode)},
        {"uid",      offsetof(struct tar_t, uid),      sizeof(archive.uid)},
        {"gid",      offsetof(struct tar_t, gid),      sizeof(archive.gid)},
        {"size",     offsetof(struct tar_t, size),     sizeof(archive.size)},
        {"mtime",    offsetof(struct tar_t, mtime),    sizeof(archive.mtime)},
        {"chksum",   offsetof(struct tar_t, chksum),   sizeof(archive.chksum)},
        {"linkname", offsetof(struct tar_t, linkname), sizeof(archive.linkname)},
        {"magic",    offsetof(struct tar_t, magic),    sizeof(archive.magic)},
        {"uname",    offsetof(struct tar_t, uname),    sizeof(archive.uname)},
        {"gname",    offsetof(struct tar_t, gname),    sizeof(archive.gname)}
    };

    int n = sizeof(fields) / sizeof(fields[0]);

    for (int i = 0; i < n; i++) {
        char *field_ptr;
        char success_name[128];

        init_clean_archive(&archive);

        field_ptr = ((char *)&archive) + fields[i].offset;

        memset(field_ptr, 'A', fields[i].size);

        snprintf(success_name, sizeof(success_name), "success_non_null_termination_%s_%s.tar", fields[i].name, tested_file);

        printf("\n--- Testing non-null termination on %s ---\n", fields[i].name);

        run_fuzz(argc, argv, &archive, success_name);
    }
}

/**
 * Fuzz selected fields with octal-like payloads to test parser handling.
 */
void fuzz_octal(int argc, char *argv[]) {
    struct tar_t archive;
    const char* tested_file = get_filename(argv[1]);

    field_desc fields[] = {
        {"name",     offsetof(struct tar_t, name),     sizeof(archive.name)},
        {"mode",     offsetof(struct tar_t, mode),     sizeof(archive.mode)},
        {"uid",      offsetof(struct tar_t, uid),      sizeof(archive.uid)},
        {"gid",      offsetof(struct tar_t, gid),      sizeof(archive.gid)},
        {"size",     offsetof(struct tar_t, size),     sizeof(archive.size)},
        {"mtime",    offsetof(struct tar_t, mtime),    sizeof(archive.mtime)},
        {"chksum",   offsetof(struct tar_t, chksum),   sizeof(archive.chksum)},
        {"linkname", offsetof(struct tar_t, linkname), sizeof(archive.linkname)},
        {"magic",    offsetof(struct tar_t, magic),    sizeof(archive.magic)},
        {"version",  offsetof(struct tar_t, version),  sizeof(archive.version)},
        {"uname",    offsetof(struct tar_t, uname),    sizeof(archive.uname)},
        {"gname",    offsetof(struct tar_t, gname),    sizeof(archive.gname)}
    };

    const char* payload[] = {"88888888","99999999999"," 123","123 ","+123","-000001","0x123","\000123","0000000", "-200"};

    int fields_size = sizeof(fields) / sizeof(fields[0]);
    int payload_size = sizeof(payload)/sizeof(payload[0]);

    for (int i = 0; i < fields_size; i++) {
        char *field_ptr;
        char success_name[128];
        for (int j = 0; j < payload_size; j++) {
            init_clean_archive(&archive);
            field_ptr = (char *)((char *)&archive + fields[i].offset);
            strncpy(field_ptr, payload[j], fields[i].size);
            snprintf(success_name,sizeof(success_name),"success_%s_octal_%d_%s.tar", fields[i].name, j, tested_file);
            run_fuzz(argc, argv, &archive, success_name);
        }
    }
}

/**
 * Fuzz multiple string payloads into every string field in tar header.
 */
void fuzz_strings_injection(int argc, char* argv[]) {
    struct tar_t archive;
    const char* tested_file = get_filename(argv[1]);

    field_desc fields[] = {
        {"name",     offsetof(struct tar_t, name),     sizeof(archive.name)},
        {"mode",     offsetof(struct tar_t, mode),     sizeof(archive.mode)},
        {"uid",      offsetof(struct tar_t, uid),      sizeof(archive.uid)},
        {"gid",      offsetof(struct tar_t, gid),      sizeof(archive.gid)},
        {"size",     offsetof(struct tar_t, size),     sizeof(archive.size)},
        {"mtime",    offsetof(struct tar_t, mtime),    sizeof(archive.mtime)},
        {"chksum",   offsetof(struct tar_t, chksum),   sizeof(archive.chksum)},
        {"linkname", offsetof(struct tar_t, linkname), sizeof(archive.linkname)},
        {"magic",    offsetof(struct tar_t, magic),    sizeof(archive.magic)},
        {"version",  offsetof(struct tar_t, version),  sizeof(archive.version)},
        {"uname",    offsetof(struct tar_t, uname),    sizeof(archive.uname)},
        {"gname",    offsetof(struct tar_t, gname),    sizeof(archive.gname)}
    };

    const char* payload[] = {"../../../../../../etc/hostname", "/%x/%n/%s/%p","%s%s%s%s%s%s%s","A\x00B\x00C\x00D"};

    int fields_size = sizeof(fields) / sizeof(fields[0]);
    int payload_size = sizeof(payload) / sizeof(payload[0]);

    for (int i = 0; i < fields_size; i++) {
        for (int j = 0; j < payload_size; j++) {
            char success_name[128];
            init_clean_archive(&archive);
            if (strcmp(fields[i].name,"linkname") == 0){
                archive.typeflag = '2';
            }
            char *field_ptr = (char*)((char*)&archive + fields[i].offset);
            strncpy(field_ptr, payload[j],fields[i].size);
            snprintf(success_name, sizeof(success_name), "success_%s_string_injection_%d_%s.tar", fields[i].name, j, tested_file);
            run_fuzz(argc, argv, &archive, success_name);
        }
    }
}


/**
 * Fuzz GNU base-256 numeric encoding in selected fields.
 */
void fuzz_on_gnu_base256(int argc, char* argv[]){
    struct tar_t archive;
    const char* tested_file = get_filename(argv[1]);

    field_desc fields[] = {
        {"size",  offsetof(struct tar_t, size),  sizeof(archive.size)},
        {"uid",   offsetof(struct tar_t, uid),   sizeof(archive.uid)},
        {"gid",   offsetof(struct tar_t, gid),   sizeof(archive.gid)},
        {"mtime", offsetof(struct tar_t, mtime), sizeof(archive.mtime)},
    };

    const char payload_big[] = {'\x80', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF'};
    const char payload_negative[] = {'\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF'};
    int fields_size = sizeof(fields) / sizeof(fields[0]);

    for(int i = 0; i < fields_size; i++){
        char success_name[128];
        char *field_ptr;

        init_clean_archive(&archive);
        field_ptr = (char *)((char *)&archive + fields[i].offset);
        memcpy(field_ptr, payload_big, fields[i].size);
        snprintf(success_name, sizeof(success_name), "success_%s_base256_huge_%s.tar", fields[i].name, tested_file);
        run_fuzz(argc, argv, &archive, success_name);

        init_clean_archive(&archive);
        field_ptr = (char *)((char *)&archive + fields[i].offset);
        memcpy(field_ptr, payload_negative, fields[i].size);
        snprintf(success_name, sizeof(success_name), "success_%s_base256_negative_%s.tar", fields[i].name, tested_file);
        run_fuzz(argc, argv, &archive, success_name);
    }

}

/**
 * Fuzz all 2-digit version fields [00..99].
 */
void fuzz_version(int argc, char* argv[]) {
    struct tar_t archive;
    const char* tested_file = get_filename(argv[1]);
    char success_name[128];

    for (char c1 = '0'; c1 <= '9'; c1++) {
        for (char c2 = '0'; c2 <= '9'; c2++) {
            init_clean_archive(&archive);

            archive.version[0] = c1;
            archive.version[1] = c2;

            snprintf(success_name, sizeof(success_name), "success_version_%c%c_%s.tar", c1, c2, tested_file);

            printf("\n--- Testing version=\"%c%c\" ---\n", c1, c2);

            run_fuzz(argc, argv, &archive, success_name);
        }
    }
}

/**
 * Set the tar size field to an octal representation of a regular file size.
 * @param archive: tar header whose size will be set.
 * @param size: numeric file size.
 */
static void set_regular_file_size(struct tar_t *archive, unsigned long long size) {
    memset(archive->size, 0, sizeof(archive->size));
    snprintf(archive->size, sizeof(archive->size), "%011llo", size);
    archive->typeflag = '0';
}

/**
 * Fuzz archive with two entries that share same name and size metadata.
 */
void fuzz_equal_name_equal_size(int argc, char* argv[]) {
    struct tar_t first;
    struct tar_t second;
    const char* tested_file = get_filename(argv[1]);
    char success_name[128];

    struct {
        const char *label;
        unsigned long long size;
    } cases[] = {
        {"size0", 0},
        {"size1", 1},
        {"size2", 2},
        {"size3", 3},
        {"size4", 4},
        {"size7", 7},
        {"size8", 8},
        {"size15", 15},
        {"size16", 16},
        {"size31", 31},
        {"size32", 32},
        {"size63", 63},
        {"size64", 64},
        {"size127", 127},
        {"size128", 128},
        {"size255", 255},
        {"size256", 256},
        {"size511", 511},
        {"size512", 512}
    };

    int cases_size = sizeof(cases) / sizeof(cases[0]);

    for (int i = 0; i < cases_size; i++) {
        unsigned long long size = cases[i].size;
        unsigned char *data1 = NULL;
        unsigned char *data2 = NULL;

        init_clean_archive(&first);
        init_clean_archive(&second);

        strcpy(first.name, "test.txt");
        strcpy(second.name, "test.txt");

        set_regular_file_size(&first, size);
        set_regular_file_size(&second, size);

        if (size > 0) {
            data1 = malloc(size);
            data2 = malloc(size);
            if (!data1 || !data2) {
                free(data1);
                free(data2);
                continue;
            }

            memset(data1, 'A', size);
            memset(data2, 'B', size);
        }

        snprintf(success_name, sizeof(success_name), "success_equal_name_equal_size_%s_%s.tar", cases[i].label, tested_file);

        printf("\n--- Testing same-name same-size update (%s) ---\n", cases[i].label);

        generate_two_entry_archive_same_name_same_size(
            &first, data1, size,
            &second, data2, size,
            "archive.tar"
        );

        int result = validate_fuzzing(argc, argv);

        if (result == 1) {
            printf("[OK] Crash detected!\n");

            generate_two_entry_archive_same_name_same_size(
                &first, data1, size,
                &second, data2, size,
                success_name
            );
            
            printf("Saved crashing archive as: %s\n", success_name);
        } 
        else if (result == 0) {
            printf("[KO] No crash.\n");
        } 
        else {
            printf("[ERR] validate_fuzzing failed.\n");
        }

        free(data1);
        free(data2);
    }
}

/**
 * Fuzz by truncating the archive at various positions within header fields.
 */
void fuzz_by_truncation(int argc, char* argv[]) {
    struct tar_t archive;
    const char* tested_file = get_filename(argv[1]);

    field_desc fields[] = {
        {"name",     offsetof(struct tar_t, name),     sizeof(archive.name)},
        {"mode",     offsetof(struct tar_t, mode),     sizeof(archive.mode)},
        {"uid",      offsetof(struct tar_t, uid),      sizeof(archive.uid)},
        {"gid",      offsetof(struct tar_t, gid),      sizeof(archive.gid)},
        {"size",     offsetof(struct tar_t, size),     sizeof(archive.size)},
        {"mtime",    offsetof(struct tar_t, mtime),    sizeof(archive.mtime)},
        {"chksum",   offsetof(struct tar_t, chksum),   sizeof(archive.chksum)},
        {"linkname", offsetof(struct tar_t, linkname), sizeof(archive.linkname)},
        {"magic",    offsetof(struct tar_t, magic),    sizeof(archive.magic)},
        {"version",  offsetof(struct tar_t, version),  sizeof(archive.version)},
        {"uname",    offsetof(struct tar_t, uname),    sizeof(archive.uname)},
        {"gname",    offsetof(struct tar_t, gname),    sizeof(archive.gname)}
    };

    int fields_size = sizeof(fields) / sizeof(fields[0]);

    for(int i = 0; i < fields_size;i++){
        char success_name[256];
        FILE *f;
        int result;

        init_clean_archive(&archive);

        strncpy(archive.magic, "ustar", 6);
        memcpy(archive.version, "00", 2);

        size_t cut_position = fields[i].offset + fields[i].size;

        f = fopen("archive.tar", "wb");
        if (f){
            fwrite(&archive, 1, cut_position, f);
            fclose(f);
        }

        result = validate_fuzzing(argc,argv);

        if (result == 1){
            snprintf(success_name, sizeof(success_name), "success_%s_truncation_%s.tar", fields[i].name, tested_file);
            f = fopen(success_name, "wb");
            if (f){
                fwrite(&archive, 1, cut_position, f);
                fclose(f);
            }
        }
    }
}
