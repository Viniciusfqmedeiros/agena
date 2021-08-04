#include "user_interface.h"

#include <ncurses.h>
#include <stdio.h>
#include <stdlib.h>

#include "buffer.h"

typedef struct user_interface_t {
  int dummy;
} user_interface_t;

static void clear_content() {
  // clear all lines except the last (so as not to clear messages)
  for (int i = 0; i < LINES - 1; ++i) {
    move(i, 0);
    clrtoeol();
  }
}

static void print_buffer(buffer_t* buf) {
  clear_content();
  refresh();

  move(0, 0);

  if (get_buffer_length(buf) <= 0) {
    return;
  }

  size_t offset = 0;
  char* c;
  while (read_from_buffer(buf, &c, offset++) > 0) {
    switch (*c) {
      case '*':
        attrset(getattrs(stdscr) ^ A_BOLD);
        break;
      case '\r':
        // skip
        break;
      default:
        addch(*c);
        break;
    }
  }
}

void write_message(const char* msg, char glyph) {
  move(LINES - 1, 0);
  attron(A_REVERSE);

  attron(A_BOLD);
  addch(glyph);
  addch(' ');
  addstr(msg);
  attroff(A_BOLD);

  hline(' ', COLS - getcurx(stdscr));
  attroff(A_REVERSE);

  refresh();
}

ui_init_result_t init_user_interface(user_interface_t** w) {
  user_interface_t* ui = calloc(1, sizeof(user_interface_t));

  if (ui == NULL) {
    return UI_INIT_ERROR;
  }

  *w = ui;

  initscr();

  cbreak();
  noecho();
  keypad(stdscr, TRUE);
  curs_set(0);

  return UI_INIT_OK;
}

void destroy_user_interface(user_interface_t* w) {
  if (w == NULL) {
    return;
  }

  endwin();

  free(w);
}

user_action_t get_ui_action(state_t* s) {
  switch (getch()) {
    case 'Q':
    case 'q':
      return USER_ACTION_QUIT;
    case '\n':
      return USER_ACTION_NAVIGATE;
    case 'R':
    case 'r':
      return USER_ACTION_REFRESH;
    case KEY_RESIZE:
      return USER_ACTION_RESIZE;
    default:
      return USER_ACTION_NO_OP;
  }
}

void update_user_interface(state_t* s) {
  clear_content();
  refresh();

  print_buffer(s->page_contents);
  refresh();
}

void get_text_input(const char* prompt, char* buf, int max_len) {
  // fill highlight line
  attron(A_REVERSE);
  move(LINES - 1, 0);
  hline(' ', COLS);

  // write prompt
  move(LINES - 1, 0);
  addstr("~ ");
  attron(A_BOLD);
  addstr(prompt);
  addstr(": ");
  attroff(A_BOLD);

  // get input
  echo();
  curs_set(1);
  getnstr(buf, max_len);
  noecho();
  curs_set(0);

  // clear line
  attroff(A_REVERSE);
  move(LINES - 1, 0);
  clrtoeol();
}

user_action_t get_confirmation(const char* prompt) {
  // fill highlight line
  attron(A_REVERSE);
  move(LINES - 1, 0);
  hline(' ', COLS);

  // write prompt
  move(LINES - 1, 0);
  addstr("? ");
  attron(A_BOLD);
  addstr(prompt);
  addstr("(y/N)");
  attroff(A_BOLD);

  // get confirmation
  switch (getch()) {
    case 'Y':
    case 'y':
      return USER_ACTION_CONFIRM;
    default:
      return USER_ACTION_DENY;
  }

  // clear line
  attroff(A_REVERSE);
  move(LINES - 1, 0);
  clrtoeol();
}
