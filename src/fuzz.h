#ifndef FUZZ_H
#define FUZZ_H

#include "defs.h"

const char* get_filename(const char* path);
void run_fuzz(int argc, char* argv[], struct tar_t* archive, const char* success_name);
void fuzz_typeflag(int argc, char* argv[]);
void fuzz_discover(int argc, char* argv[]);
void fuzz_non_null_termination(int argc, char* argv[]);
void fuzz_octal(int argc, char* argv[]);
void fuzz_strings_injection(int argc, char* argv[]);
void fuzz_on_time(int argc, char* argv[]);
void fuzz_on_gnu_base256(int argc, char* argv[]);
void fuzz_version(int argc, char* argv[]);
void fuzz_equal_name_equal_size(int argc, char* argv[]);

#endif
