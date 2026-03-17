#ifndef FUZZ_H
#define FUZZ_H

#include "defs.h"

void run_fuzz(int argc, char* argv[], struct tar_t* archive, const char* success_name);
void fuzz_typeflag(int argc, char* argv[]);
void fuzz_discover(int argc, char* argv[]);
void fuzz_non_null_termination(int argc, char* argv[]);
void fuzz_octal(int argc, char* argv[]);
void fuzz_strings_injection(int argc, char* argv[]);

#endif
