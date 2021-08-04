#include "state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buffer.h"
#include "network.h"
#include "user_interface.h"

#define MSG_WELCOME "Welcome to *Agena*!"

static void write_notice(const char* msg) { write_message(msg, '+'); }

static void write_error(const char* msg) { write_message(msg, '!'); }

static bool user_confirm(const char* msg) {
  return get_confirmation(msg) == USER_ACTION_CONFIRM;
}

static void handle_fetch_result(state_t* s, net_fetch_result_t result) {
  switch (result) {
    case NET_FETCH_OK:
      // write_notice("Fetched");
      break;
    case NET_FETCH_CANCEL:
      write_notice("Cancelled!");
      break;
    case NET_FETCH_BADURI:
      write_error("Bad URI");
      break;
    case NET_FETCH_BADPROTO:
      write_error("Unrecognized protocol");
      break;
    case NET_FETCH_CONNECTFAILED:
      // preserve the socket error message
      break;
    case NET_FETCH_NORELOAD:
      write_error("Nothing to reload!");
      break;
    case NET_FETCH_NONGEMINI:
      write_notice("Opened non-Gemini URI in an external program");
      break;
    case NET_FETCH_NOMEM:
      write_error("Out of memory");
      break;
    case NET_FETCH_NOTFOUND:
      write_error("Page not found");
      break;
    case NET_FETCH_REDIRECT:
      write_notice("Redirecting...");
      break;
    case NET_FETCH_INPUT:
      write_notice("Input is required");
      break;
    case NET_FETCH_ERROR:
      write_error("Server error");
      break;
    case NET_FETCH_CERT:
      write_notice("Certificate is required");
      break;
    default:
      break;
  }
}

state_t* create_state(void) {
  state_t* state = calloc(1, sizeof(state_t));

  if (init_user_interface(&state->window) == UI_INIT_ERROR ||
      init_buffer(&state->page_contents) == BUFFER_INIT_ERROR ||
      init_network(&state->network, write_notice, write_error, user_confirm) ==
          NET_INIT_ERROR) {
    printf("Failed to initialize Agena\n");
    destroy_state(state);
    return NULL;
  }

  write_to_buffer(state->page_contents, &MSG_WELCOME[0], strlen(MSG_WELCOME));

  return state;
}

void destroy_state(state_t* s) {
  if (s == NULL) {
    return;
  }

  if (s->window != NULL) {
    destroy_user_interface(s->window);
  }

  if (s->page_contents != NULL) {
    destroy_buffer(s->page_contents);
  }

  if (s->network != NULL) {
    destroy_network(s->network);
  }

  free(s);
}

state_update_status_t update_state(state_t* s) {
  update_user_interface(s);

  char uri[1024];

  switch (get_ui_action(s)) {
    case USER_ACTION_QUIT:
      return STATE_QUIT;
    case USER_ACTION_NAVIGATE:
      memset(&uri[0], 0, sizeof(uri) / sizeof(char));
      get_text_input("url", &uri[0], sizeof(uri) / sizeof(char));
      if (strnlen(&uri[0], sizeof(uri) / sizeof(char)) > 0) {
        handle_fetch_result(s, fetch_content(s, &uri[0]));
      } else {
        write_notice("Cancelled");
      }
      break;
    case USER_ACTION_REFRESH:
      handle_fetch_result(s, reload_last(s));
      break;
    case USER_ACTION_RESIZE:
      // TODO: think about how to handle this if text entry is in-progress
      update_user_interface(s);
      break;
    default:
      break;
  }

  return STATE_OK;
}

