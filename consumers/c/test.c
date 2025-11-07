#include "cipher312.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void test_basic_decode() {
  printf("Testing basic decode...\n");
  char *result = NULL;
  DecodeResultC err = decode_string("41", &result);

  assert(err == Success);
  assert(result != NULL);
  assert(strcmp(result, "A") == 0);

  free_string(result);
  printf("✓ Basic decode test passed\n");
}

void test_null_input() {
  printf("Testing null input...\n");
  char *result = NULL;
  DecodeResultC err = decode_string(NULL, &result);

  assert(err == NullPointer);
  assert(result == NULL);

  printf("✓ Null input test passed\n");
}

void test_null_output() {
  printf("Testing null output...\n");
  DecodeResultC err = decode_string("hello", NULL);

  assert(err == NullPointer);

  printf("✓ Null output test passed\n");
}

void test_empty_string() {
  printf("Testing empty string...\n");
  char *result = NULL;
  DecodeResultC err = decode_string("", &result);

  assert(err == Success);
  assert(result != NULL);
  assert(strlen(result) == 0);

  free_string(result);
  printf("✓ Empty string test passed\n");
}

void test_memory_cleanup() {
  printf("Testing memory cleanup...\n");
  // Run multiple times to check for leaks
  for (int i = 0; i < 1000; i++) {
    char *result = NULL;
    DecodeResultC err = decode_string("794842328138412791", &result);
    assert(err == Success);
    assert(strcmp(result, "👻") == 0);
    free_string(result);
  }
  printf("✓ Memory cleanup test passed\n");
}

int main() {
  printf("Running C FFI tests...\n\n");

  test_basic_decode();
  test_null_input();
  test_null_output();
  test_empty_string();
  test_memory_cleanup();

  printf("\n✅ All tests passed!\n");
  return 0;
}
