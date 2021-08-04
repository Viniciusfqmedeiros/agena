#ifndef USER_INTERFACE_H
#define USER_INTERFACE_H

#include "action.h"
#include "state.h"

typedef enum ui_init_result_t {
  UI_INIT_OK = 0,
  UI_INIT_ERROR
} ui_init_result_t;

void write_message(const char* msg, char glyph);

ui_init_result_t init_user_interface(user_interface_t** w);

void destroy_user_interface(user_interface_t* w);

user_action_t get_ui_action(state_t* state);

void update_user_interface(state_t* state);

void get_text_input(const char* prompt, char* buf, int max_len);

user_action_t get_confirmation(const char* prompt);

#endif
