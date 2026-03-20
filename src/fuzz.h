#ifndef FUZZ_H
#define FUZZ_H

#include "defs.h"

void run_fuzz(int argc, char* argv[], struct tar_t* archive, const char* success_name);
void fuzz_typeflag(int argc, char* argv[]);
void fuzz_non_null_termination(int argc, char* argv[]);
void fuzz_octal(int argc, char* argv[]);
void fuzz_strings_injection(int argc, char* argv[]);
void fuzz_on_gnu_base256(int argc, char* argv[]);
void fuzz_version(int argc, char* argv[]);
void fuzz_duplicate_headers(int argc, char* argv[]);
void fuzz_on_gnu_base256(int argc, char* argv[]);
void fuzz_by_truncation(int argc, char* argv[]);
void fuzz_by_truncation_on_data(int argc, char* argv[]);
void fuzz_by_checksum_forgery(int argc, char* argv[]);

#endif
