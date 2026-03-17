#ifndef UTILS_H
#define UTILS_H

#include "defs.h"

unsigned int calculate_checksum(struct tar_t* entry);
int validate_fuzzing(int argc, char* argv[]);
void init_clean_archive(struct tar_t* archive);
void write_zero_block(FILE *file);
void generate_archive(struct tar_t* archive, const char* filename);

#endif
