#include <stdio.h>
#include <sys/stat.h>

#include "fuzz.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: ./fuzzer <path_to_extractor>\n");
        return -1;
    }   

    printf("Starting fuzzing on extractor: %s\n", argv[1]);

    fuzz_typeflag(argc, argv);
    fuzz_non_null_termination(argc, argv);
    fuzz_octal(argc, argv);
    fuzz_strings_injection(argc, argv);
    fuzz_on_gnu_base256(argc, argv);
    fuzz_version(argc, argv);
    fuzz_duplicate_headers(argc, argv);
    fuzz_on_gnu_base256(argc,argv);
    fuzz_by_truncation(argc, argv);
    fuzz_by_truncation_on_data(argc, argv);
    fuzz_by_checksum_forgery(argc, argv);

    printf("Fuzzing completed.\n");

    return 0;
}
