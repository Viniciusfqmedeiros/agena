#include <stddef.h>

#include "state.h"

int main(int argc, const char** argv) {
  state_t* state = create_state();

  if (state == NULL) {
    return -1;
  }

  state_update_status_t status;
  while ((status = update_state(state)) == STATE_OK) {
    // normal operation
  }

  if (status == STATE_ERROR) {
    // TODO: log information about the error
    return -1;
  }

  destroy_state(state);

  return 0;
}
