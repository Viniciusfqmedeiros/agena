#ifndef DATABASE_H
#define DATABASE_H

#include <stdbool.h>

#include "state.h"

typedef enum db_init_result_t {
  DB_INIT_OK = 0,
  DB_INIT_ERROR
} db_init_result_t;

db_init_result_t init_database(database_t** db);

bool host_has_known_fingerprint(database_t* db, const char* host,
                                char** fingerprint);

void set_host_known_fingerprint(database_t* db, const char* host,
                                const char* fingerprint);

#endif
