#ifndef NETWORK_H
#define NETWORK_H

#include <stdbool.h>

#include "state.h"

typedef enum net_init_result_t {
  NET_INIT_OK = 0,
  NET_INIT_ERROR
} net_init_result_t;

typedef enum net_fetch_result_t {
  NET_FETCH_OK = 0,
  NET_FETCH_CANCEL,
  NET_FETCH_NORELOAD,
  NET_FETCH_BADURI,
  NET_FETCH_BADPROTO,
  NET_FETCH_NONGEMINI,
  NET_FETCH_CONNECTFAILED,
  NET_FETCH_TLSFAILED,
  NET_FETCH_NOMEM,
  NET_FETCH_NOTFOUND,
  NET_FETCH_REDIRECT,
  NET_FETCH_INPUT,
  NET_FETCH_ERROR,
  NET_FETCH_CERT
} net_fetch_result_t;

typedef void (*status_callback_t)(const char*);

typedef void (*fail_callback_t)(const char*);

typedef bool (*confirm_callback_t)(const char*);

net_init_result_t init_network(network_t** n, status_callback_t status_cb,
                               fail_callback_t, confirm_callback_t);

void destroy_network(network_t* n);

net_fetch_result_t fetch_content(state_t* s, const char* input);

net_fetch_result_t reload_last(state_t* s);

#endif
