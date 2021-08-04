#include "buffer.h"

#include <curses.h>
#include <stdlib.h>
#include <string.h>

#define INITIAL_CAPACITY 2048

typedef struct buffer_t {
  size_t capacity;
  size_t length;
  char* data;
} buffer_t;

static void allocate_initial_buffer(buffer_t* b) {
  b->capacity = INITIAL_CAPACITY;
  b->data = calloc(INITIAL_CAPACITY, sizeof(char));
}

static size_t resize_buffer(buffer_t* b, size_t size) {
  b->capacity = size;
  char* tmp = realloc(b->data, b->capacity * sizeof(char));
  if (tmp == NULL) {
    // resize failed, reset the problematic buffer and return 0 so that we stop
    // trying
    free(b->data);
    allocate_initial_buffer(b);
    return 0;
  }

  b->data = tmp;

  return b->capacity;
}

static size_t grow_buffer(buffer_t* b) {
  return resize_buffer(b, b->capacity * 2);
}

buffer_init_result_t init_buffer(buffer_t** b) {
  buffer_t* buf = calloc(1, sizeof(buffer_t));
  if (buf == NULL) {
    return BUFFER_INIT_ERROR;
  }

  *b = buf;

  allocate_initial_buffer(buf);
  if (buf->data == NULL) {
    return BUFFER_INIT_ERROR;
  }

  return BUFFER_INIT_OK;
}

void destroy_buffer(buffer_t* b) {
  if (b == NULL) {
    return;
  }

  if (b->data != NULL) {
    free(b->data);
  }

  free(b);
}

void write_to_buffer(buffer_t* b, const char* data, size_t len) {
  while (b->length + len > b->capacity) {
    if (grow_buffer(b) == 0) {
      // failed to grow, so stop
      break;
    }
  }

  size_t available = b->capacity - b->length;
  if (available > 0) {
    size_t copy_len = available < len ? available : len;
    memcpy(&b->data[b->length], data, copy_len);
    b->length += copy_len;
  }
}

size_t read_from_buffer(buffer_t* b, char** out, size_t offset) {
  size_t index = offset <= b->length - 1 ? offset : b->length - 1;
  *out = &b->data[index];
  return b->length - index - 1;
}

void reset_buffer(buffer_t* b) {
  resize_buffer(b, INITIAL_CAPACITY);
  memset(b->data, 0, b->capacity);
  b->length = 0;
}

size_t get_buffer_length(buffer_t* b) { return b->length; }
