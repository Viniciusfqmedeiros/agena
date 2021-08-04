#ifndef MACROS_H
#define MACROS_H

#define LOG_BUFFER_LENGTH 256

#define WRITE_FMT(buf, fmt, ...)                                     \
  {                                                                  \
    memset(&buf[0], 0, sizeof(buf) / sizeof(char));                  \
    snprintf(&buf[0], sizeof(buf) / sizeof(char), fmt, __VA_ARGS__); \
  }

#define LOG(cb, fmt, ...)             \
  {                                   \
    char buf[LOG_BUFFER_LENGTH];      \
    WRITE_FMT(buf, fmt, __VA_ARGS__); \
    cb(&buf[0]);                      \
  }

#define CONFIRM(cb, res, fmt, ...)    \
  {                                   \
    char buf[LOG_BUFFER_LENGTH];      \
    WRITE_FMT(buf, fmt, __VA_ARGS__); \
    res = cb(&buf[0]);                \
  }

#endif
