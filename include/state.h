#ifndef STATE_H
#define STATE_H

typedef struct user_interface_t user_interface_t;
typedef struct network_t network_t;
typedef struct database_t database_t;
typedef struct active_cert_t active_cert_t;
typedef struct buffer_t buffer_t;

typedef enum state_update_status_t {
  STATE_OK = 0,
  STATE_QUIT,
  STATE_ERROR
} state_update_status_t;

/*
 * Global application state
 */
typedef struct state_t {
  user_interface_t* window;
  network_t* network;
  database_t* database;
  active_cert_t* active_cert;
  buffer_t* page_contents;
} state_t;

state_t* create_state(void);

void destroy_state(state_t* s);

/*
 * Perform application update tick; handle user-input, update the view, etc.
 */
state_update_status_t update_state(state_t* s);

#endif
