#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/stat.h>
#include <limits.h>
#include <time.h>

#include "utils.h"
#include "fuzz.h"

void run_fuzz(int argc, char* argv[], struct tar_t* archive, const char* success_name) {
    generate_archive(archive, "archive.tar");

    int result = validate_fuzzing(argc, argv);

    if (result == 1) {
        printf("[OK] Crash detected!\n");
        generate_archive(archive, success_name);
        printf("Saved crashing archive as: %s\n", success_name);
    } else if (result == 0) {
        printf("[KO] No crash.\n");
    } else {
        printf("[ERR] validate_fuzzing failed.\n");
    }
}

void fuzz_typeflag(int argc, char* argv[]) {
    for (int value = 0; value <= 255; value++) {
        struct tar_t archive;
        char success_name[128];

        init_clean_archive(&archive);
        archive.typeflag = (char)value;

        snprintf(success_name, sizeof(success_name), "successful_crashes/success_typeflag_%02X.tar", value);

        printf("\n--- Testing typeflag = 0x%02X", value);

        if (value >= 32 && value <= 126) {
            printf(" ('%c')", value);
        }

        run_fuzz(argc, argv, &archive, success_name);
    }
}

void fuzz_discover(int argc, char* argv[]) {
    struct tar_t archive;
    const char* payload[] = {
            "-1",
            "0",
            "99999999999",
            "ABCDEFGHIJK",
            " ",
            "\xFF\xFF\xFF\xFF"
        };

    int payload_size = sizeof(payload) / sizeof(payload[0]);

    char success_name[128];
    for (int i = 0; i < payload_size; i++){
        init_clean_archive(&archive);
        strncpy(archive.size, payload[i],12);
        snprintf(success_name, sizeof(success_name), "successful_crashes/success_size_injection_%d.tar", i);
        run_fuzz(argc, argv, &archive, success_name);

        init_clean_archive(&archive);
        strncpy(archive.mode, payload[i],8);
        snprintf(success_name, sizeof(success_name), "successful_crashes/success_mode_injection_%d.tar", i);
        run_fuzz(argc, argv, &archive, success_name);

        init_clean_archive(&archive);
        strncpy(archive.uid, payload[i],8);
        snprintf(success_name, sizeof(success_name), "successful_crashes/success_uid_injection_%d.tar", i);
        run_fuzz(argc, argv, &archive, success_name);

        init_clean_archive(&archive);
        strncpy(archive.gid, payload[i],8);
        snprintf(success_name, sizeof(success_name), "successful_crashes/success_gid_injection_%d.tar", i);
        run_fuzz(argc, argv, &archive, success_name);

        init_clean_archive(&archive);
        strncpy(archive.mtime, payload[i],12);
        snprintf(success_name, sizeof(success_name), "successful_crashes/success_mtime_injection_%d.tar", i);
        run_fuzz(argc, argv, &archive, success_name);

        init_clean_archive(&archive);
        strncpy(archive.version, payload[i],2);
        snprintf(success_name, sizeof(success_name), "successful_crashes/success_version_injection_%d.tar", i);
        run_fuzz(argc, argv, &archive, success_name);
    }
}

void fuzz_octal(int argc, char *argv[]) {
    printf("\n--- Starting fuzzing octal on archive header fields:---\n");
    struct tar_t archive;
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
    int fields_size = sizeof(fields) / sizeof(fields[0]);
    const char* payload[] = {"88888888","99999999999"," 123","123 ","+123","-000001","0x123","\000123","0000000"};

    int payload_size = sizeof(payload)/sizeof(payload[0]);
    for (int i = 0; i < payload_size; i++) {
        char *field_ptr;
        char success_name[128];
        for (int j = 0; j < fields_size; j++) {
            init_clean_archive(&archive);
            field_ptr = (char *)((char *)&archive + fields[j].offset);
            strncpy(field_ptr, payload[i], fields[j].size);
            snprintf(success_name,sizeof(success_name),"successful_crashes/success_%s_injection_octal_payload_number%d.tar", fields[j].name, i);
            run_fuzz(argc, argv, &archive, success_name);
        }
    }
}

void fuzz_non_null_termination(int argc, char* argv[]) {
    struct tar_t archive;

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

        snprintf(success_name, sizeof(success_name),
                 "successful_crashes/success_nonnull_%s.tar",
                 fields[i].name);

        printf("\n--- Testing non-null termination on %s ---\n", fields[i].name);

        run_fuzz(argc, argv, &archive, success_name);
    }
}

void fuzz_strings_injection(int argc, char* argv[]) {
    struct tar_t archive;
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
    int fields_size = sizeof(fields) / sizeof(fields[0]);

    const char* payload[] = {"../../../../../../etc/passwd", "/%x/%n/%s/%p","%s%s%s%s%s%s%s","A\x00B\x00C\x00D"};

    for (int i = 0; i < fields_size; i++) {
        char success_name[128];
        init_clean_archive(&archive);
        for (int j = 0; j < sizeof(payload) / sizeof(payload[0]); j++) {
            if (strcmp(fields[j].name,"linkname") == 0){
                archive.typeflag = '2';
            }
            char *field_ptr = (char*)((char*)&archive + fields[j].offset);
            strncpy(field_ptr, payload[i],fields[j].size);
            snprintf(success_name, sizeof(success_name), "successful_crashes/success_string_injection_%s_payload_%d.tar", fields[j].name, i);
            run_fuzz(argc, argv, &archive, success_name);
        }
    }
}
