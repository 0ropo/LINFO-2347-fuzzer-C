#ifndef UTILS_H
#define UTILS_H

#include "defs.h"

unsigned int calculate_checksum(struct tar_t* entry);
int validate_fuzzing(int argc, char* argv[]);
void init_clean_archive(struct tar_t* archive);
void write_zero_block(FILE *file);
void generate_archive(struct tar_t* archive, const char* filename);
void generate_two_entry_archive_same_name_same_size(
    struct tar_t* first,
    const unsigned char* data1,
    size_t data1_size,
    struct tar_t* second,
    const unsigned char* data2,
    size_t data2_size,
    const char* filename
);

#endif
