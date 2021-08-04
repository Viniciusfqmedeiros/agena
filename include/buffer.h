#ifndef BUFFER_H
#define BUFFER_H

#include <stddef.h>

#include "state.h"

typedef enum buffer_init_result_t {
  BUFFER_INIT_OK = 0,
  BUFFER_INIT_ERROR
} buffer_init_result_t;

buffer_init_result_t init_buffer(buffer_t** b);

void destroy_buffer(buffer_t* b);

/*
 * Copies up to `len` bytes from `data` into the buffer's internal storage
 */
void write_to_buffer(buffer_t* b, const char* data, size_t len);

/*
 * Sets `out` to the address of the buffer's internal storage at offset
 * `offset`.  Returns the remaining length of the internal buffer after the
 * provided offset (length - offset), or 0 if `offset` exceeds (length - 1).
 */
size_t read_from_buffer(buffer_t* b, char** out, size_t offset);

/*
 * Clears the contents of the buffer and resets its length to 0
 */
void reset_buffer(buffer_t* b);

size_t get_buffer_length(buffer_t* b);

#endif
