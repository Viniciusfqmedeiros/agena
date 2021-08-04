#include "network.h"

#include <arpa/inet.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include <gnutls/pkcs7.h>
#include <gnutls/x509.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pcre2posix.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "buffer.h"
#include "database.h"
#include "macros.h"

#define MAX_URI_LENGTH 1024
#define CMD_BUFFER_LENGTH 2048
#define RECEIVE_BUFFER_LENGTH 2048

#define TLS_PRIORITY_MOD "-VERS-TLS-ALL:+VERS-TLS1.2:+VERS-TLS1.3"

#define DEFAULT_GEMINI_PORT "1965"

#define URI_PATTERN                                                           \
  "(?:(?:([a-z]+):\\/\\/)?([a-z0-9]{1}[a-z0-9.\\-]+)(?::([0-9]{2,5}))?)?(\\/" \
  "[^\\r\\n\\?]*)?(?:\\?([^\\r\\n\\?]+))?"

#define URI_PART_COUNT 6
#define URI_SCHEME 1
#define URI_HOST 2
#define URI_PORT 3
#define URI_PATH 4
#define URI_INPUT 5

#define SEND_MAX_RETRIES 10
#define RECV_MAX_RETRIES 10

#define SCHEME_GEMINI "gemini"
#define CRLF "\r\n"

typedef struct uri_t {
  char* scheme;
  char* host;
  char* port;
  char* path;
  char* input;
} uri_t;

typedef struct network_t {
  regex_t uri_pattern;
  status_callback_t status;
  bool trusted;
  bool confirmed;
  fail_callback_t fail;
  confirm_callback_t confirm;
  uri_t* last_uri;
} network_t;

static bool scheme_is_gemini(const char* scheme) {
  return strcmp(SCHEME_GEMINI, scheme) == 0;
}

static void open_non_gemini(const char* uri) {
  char* cmd = calloc(CMD_BUFFER_LENGTH, sizeof(char));
  snprintf(cmd, CMD_BUFFER_LENGTH, "xdg-open %s", uri);
  system(cmd);
  free(cmd);
}

static int compile_uri_pattern(regex_t* regexp) {
  int status = regcomp(regexp, URI_PATTERN, REG_ICASE);
  if (status != 0) {
    char msg[LOG_BUFFER_LENGTH];
    memset(&msg[0], 0, sizeof(msg) / sizeof(char));
    regerror(status, regexp, &msg[0], sizeof(msg) / sizeof(char));
    fprintf(stderr, "URI regex compile failed: %s", &msg[0]);
    return false;
  }

  return true;
}

static void copy_match_or_null(const regmatch_t* match, const char* uri,
                               char** out) {
  if (match->rm_so < 0) {
    *out = NULL;
    return;
  }

  *out = strndup(&uri[match->rm_so], match->rm_eo - match->rm_so);
}

static uri_t* build_uri_components(const regmatch_t* matches,
                                   const uri_t* last_uri, uri_t* uri,
                                   const char* raw) {
  copy_match_or_null(&matches[URI_SCHEME], raw, &uri->scheme);
  copy_match_or_null(&matches[URI_HOST], raw, &uri->host);
  copy_match_or_null(&matches[URI_PORT], raw, &uri->port);
  copy_match_or_null(&matches[URI_PATH], raw, &uri->path);
  copy_match_or_null(&matches[URI_INPUT], raw, &uri->input);

  // if no host was provided, try and copy it from the last request
  if (uri->host == NULL && last_uri != NULL && last_uri->host != NULL) {
    uri->host = strndup(last_uri->host, MAX_URI_LENGTH);
  }

  return uri;
}

static void free_uri(uri_t* uri) {
  if (uri->scheme != NULL) {
    free(uri->scheme);
  }

  if (uri->host != NULL) {
    free(uri->host);
  }

  if (uri->port != NULL) {
    free(uri->port);
  }

  if (uri->path != NULL) {
    free(uri->path);
  }

  if (uri->input != NULL) {
    free(uri->input);
  }

  free(uri);
}

static void get_addr_string(struct addrinfo* addr, char* out, size_t out_len) {
  memset(out, 0, out_len);
  switch (addr->ai_family) {
    case AF_INET:
      inet_ntop(addr->ai_family,
                &((struct sockaddr_in*)addr->ai_addr)->sin_addr, out, out_len);
      break;
    case AF_INET6:
      inet_ntop(addr->ai_family,
                &((struct sockaddr_in6*)addr->ai_addr)->sin6_addr, out,
                out_len);
      break;
    default:
      break;
  }
}

static void set_tls_version(gnutls_session_t session) {
  // disable all protocol versions, then explicitly enable TLS v1.3

  const char* err_index;
  gnutls_set_default_priority_append(session, TLS_PRIORITY_MOD, &err_index, 0);
}

static bool resolve_host_and_connect(network_t* net, int* sock,
                                     const char* host, const char* port) {
  if (port == NULL) {
    port = DEFAULT_GEMINI_PORT;
  }

  struct addrinfo hint;
  memset(&hint, 0, sizeof(struct addrinfo));
  hint.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | AI_NUMERICSERV;
  hint.ai_family = AF_UNSPEC;
  hint.ai_socktype = SOCK_STREAM;

  LOG(net->status, "Attempting to resolve \"%s\"...", host);

  // try to resolve DNS records
  struct addrinfo* results = NULL;
  int status = getaddrinfo(host, port, &hint, &results);
  if (status != 0) {
    LOG(net->fail, "Failed to resolve host: %s", gai_strerror(status));
    return false;
  }

  // iterate over each of the address results that the DNS query returned until
  // we either run out or successfully connect to one of them
  for (struct addrinfo* addr = results; addr != NULL; addr = addr->ai_next) {
    char ip[INET6_ADDRSTRLEN];
    get_addr_string(addr, &ip[0], sizeof(ip) / sizeof(char));
    LOG(net->status, "Attempting connection to %s...", &ip[0]);

    // open a new socket
    *sock = socket(addr->ai_family, SOCK_STREAM, IPPROTO_TCP);

    // attempt to connect to this address
    int conn_result = connect(*sock, addr->ai_addr, addr->ai_addrlen);
    if (conn_result != 0) {
      LOG(net->fail, "Connection attempt failed: %s", strerror(errno));
      close(*sock);
    } else {
      LOG(net->status, "Successfully connected to %s", &ip[0]);
      freeaddrinfo(results);
      return true;
    }
  }

  // every connection attempt failed
  freeaddrinfo(results);
  return false;
}

static int verify_certificate(gnutls_session_t session) {
  unsigned int peer_data_len;
  const gnutls_datum_t* peer_entries =
      gnutls_certificate_get_peers(session, &peer_data_len);

  // ensure that at least one cert was made available
  if (peer_data_len < 1) {
    return -1;
  }

  size_t fingerprint_len;
  gnutls_digest_algorithm_t algo = gnutls_prf_hash_get(session);
  gnutls_fingerprint(algo, NULL, NULL, &fingerprint_len);

  unsigned char* fingerprint = malloc(fingerprint_len * sizeof(unsigned char));
  gnutls_fingerprint(algo, &peer_entries[0], fingerprint, &fingerprint_len);

  state_t* s = (state_t*)gnutls_session_get_ptr(session);

  // *********************************************************************
  // TODO: check whether the fingerprint is trusted and corresponds to the
  //       current host; if so, return 0
  // *********************************************************************

  // database_t

  network_t* net = s->network;
  net->trusted = true;
  return 0;

  char* hex = calloc(fingerprint_len * 3, sizeof(char));
  if (hex == NULL) {
    LOG(net->fail, "%s",
        "Ran out of memory attempting to render cert. signature");
    return -1;
  }

  snprintf(&hex[0], 3, "%02X", fingerprint[0]);
  snprintf(&hex[2], 4, ":%02X", fingerprint[1]);
  for (size_t i = 2; i < 8; ++i) {
    snprintf(&hex[i * 3 - 1], 4, ":%02X", fingerprint[i]);
  }

  CONFIRM(net->confirm, net->trusted, "(%s) Accept this certificate from %s? ",
          hex, net->last_uri->host);

  if (net->trusted) {
    net->confirmed = true;  // start over now that we're trusted
  }

  free(hex);

  return 0;
}

static bool perform_handshake(network_t* net, int sock,
                              gnutls_session_t session) {
  gnutls_transport_set_int(session, sock);
  gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

  int handshake = 0;
  do {
    handshake = gnutls_handshake(session);
  } while (!net->confirmed && handshake < 0 &&
           gnutls_error_is_fatal(handshake) == 0);

  // if the user responded to a trust confirmation prompt, bail out so that we
  // can restart
  if (net->confirmed) {
    return true;
  }

  if (handshake < 0) {
    if (handshake == GNUTLS_E_WARNING_ALERT_RECEIVED) {
      int alert = gnutls_alert_get(session);
      LOG(net->fail, "TLS warning alert: %s", gnutls_alert_get_name(alert));
    } else if (handshake == GNUTLS_E_FATAL_ALERT_RECEIVED) {
      int alert = gnutls_alert_get(session);
      LOG(net->fail, "TLS fatal alert: %s", gnutls_alert_get_name(alert));
    } else {
      LOG(net->fail, "TLS alert: %s", gnutls_strerror(handshake));
    }

    return false;
  }

  char* desc = gnutls_session_get_desc(session);
  LOG(net->status, "%s", desc);
  gnutls_free(desc);

  return true;
}

static bool extract_uri_segments(const network_t* net, const char* raw,
                                 regmatch_t* uri_parts,
                                 net_fetch_result_t* result) {
  switch (regexec(&net->uri_pattern, raw, URI_PART_COUNT, uri_parts,
                  REG_NOTBOL | REG_NOTEOL)) {
    case REG_NOMATCH:
      *result = NET_FETCH_BADURI;
      return false;
    case REG_ESPACE:
      *result = NET_FETCH_NOMEM;
      return false;
    default:
      break;
  }

  if (uri_parts[0].rm_eo - uri_parts[0].rm_so <= 0) {
    // consider empty results to be invalid
    *result = NET_FETCH_BADURI;
    return false;
  }

  return true;
}

static void perform_download(gnutls_session_t session, network_t* net,
                             buffer_t* content) {
  char buffer[RECEIVE_BUFFER_LENGTH];
  reset_buffer(content);

  int failed_attempts = 0;
  for (;;) {
    int res = (int)gnutls_record_recv(session, &buffer[0],
                                      sizeof(buffer) / sizeof(char));
    if (res > 0) {
      write_to_buffer(content, &buffer[0], res);
      failed_attempts = 0;
    } else {
      if (res < 0) {
        // we need to try again, but only a set number of times
        if (failed_attempts < RECV_MAX_RETRIES &&
            (res == GNUTLS_E_AGAIN || res == GNUTLS_E_INTERRUPTED)) {
          ++failed_attempts;
          continue;
        }

        // log any errors
        if (gnutls_error_is_fatal(res) == 0) {
          LOG(net->status, "Non-fatal error encountered while receiving: %s",
              gnutls_strerror(res));
        } else {
          LOG(net->status, "Fatal error encountered while receiving: %s",
              gnutls_strerror(res));
        }
      }

      break;
    }
  }

  if (get_buffer_length(content) > 0) {
    LOG(net->status, "%zu bytes received", get_buffer_length(content));
  }
}

static bool send_request(gnutls_session_t session, network_t* net,
                         const char* data, size_t len) {
  int res = (int)gnutls_record_send(session, data, len);
  for (int i = 0; i < SEND_MAX_RETRIES &&
                  (res == GNUTLS_E_AGAIN || res == GNUTLS_E_INTERRUPTED);
       ++i) {
    res = (int)gnutls_record_send(session, data, len);
  }

  if (res < 0) {
    if (gnutls_error_is_fatal(res)) {
      LOG(net->fail, "Non-fatal encountered while sending: %s",
          gnutls_strerror(res));
    } else {
      LOG(net->fail, "Fatal encountered while sending: %s",
          gnutls_strerror(res));
    }
  }

  return res > 0;
}

static char* build_request(const network_t* net, const uri_t* uri,
                           size_t* req_len) {
  char* req = calloc(MAX_URI_LENGTH + 2, sizeof(char));
  if (req == NULL) {
    return NULL;
  }

  char* scheme = uri->scheme == NULL ? SCHEME_GEMINI : uri->scheme;
  char* host = uri->host == NULL ? net->last_uri->host : uri->host;

  *req_len = snprintf(req, MAX_URI_LENGTH, "%s://%s", scheme, host);

  if (*req_len < MAX_URI_LENGTH && uri->port != NULL) {
    *req_len +=
        snprintf(&req[*req_len], MAX_URI_LENGTH - *req_len, ":%s", uri->port);
  }

  if (*req_len < MAX_URI_LENGTH && uri->path != NULL) {
    *req_len +=
        snprintf(&req[*req_len], MAX_URI_LENGTH - *req_len, "%s", uri->path);
  }

  if (*req_len < MAX_URI_LENGTH && uri->input != NULL) {
    *req_len +=
        snprintf(&req[*req_len], MAX_URI_LENGTH - *req_len, "?%s", uri->input);
  }

  *req_len += snprintf(&req[*req_len], MAX_URI_LENGTH - *req_len, "%s", CRLF);

  return req;
}

static uri_t* build_uri_from_input(const network_t* net, const char* input,
                                   net_fetch_result_t* result) {
  // extract matches form URI via regex
  regmatch_t uri_parts[URI_PART_COUNT];
  if (!extract_uri_segments(net, input, &uri_parts[0], result)) {
    return NULL;
  }

  uri_t* uri = calloc(1, sizeof(uri_t));
  if (uri == NULL) {
    *result = NET_FETCH_NOMEM;
    return NULL;
  }

  build_uri_components(&uri_parts[0], net->last_uri, uri, input);
  if (uri->host == NULL) {
    // no host and no previous host (would have been copied in the above call)
    *result = NET_FETCH_BADURI;
    free_uri(uri);
    return NULL;
  }

  // open non-gemini protocols in an os-dependent fashion
  if (uri->scheme != NULL && strlen(uri->scheme) > 0 &&
      !scheme_is_gemini(uri->scheme)) {
    // open URIs with non-gemini schemes in some other application
    open_non_gemini(input);
    *result = NET_FETCH_NONGEMINI;
    free_uri(uri);
    return NULL;
  }

  return uri;
}

static uri_t* copy_uri(const uri_t* uri) {
  if (uri == NULL) {
    return NULL;
  }

  uri_t* copy = calloc(1, sizeof(uri_t));
  if (copy == NULL) {
    return NULL;
  }

  if (uri->scheme != NULL) {
    copy->scheme = strndup(uri->scheme, MAX_URI_LENGTH);
  }

  if (uri->host != NULL) {
    copy->host = strndup(uri->host, MAX_URI_LENGTH);
  }

  if (uri->port != NULL) {
    copy->host = strndup(uri->port, MAX_URI_LENGTH);
  }

  if (uri->path != NULL) {
    copy->path = strndup(uri->path, MAX_URI_LENGTH);
  }

  if (uri->input != NULL) {
    copy->input = strndup(uri->input, MAX_URI_LENGTH);
  }

  return copy;
}

static bool copy_uri_as_last(network_t* net, const uri_t* uri,
                             net_fetch_result_t* result) {
  uri_t* copy = copy_uri(uri);
  if (copy == NULL) {
    *result = NET_FETCH_NOMEM;
    return false;
  }

  net->last_uri = copy;
  return true;
}

static void fetch_uri(state_t* s, const uri_t* uri,
                      net_fetch_result_t* result) {
  network_t* net = s->network;

  // attempt a connection to the chosen host + port
  int sock = 0;
  if (!resolve_host_and_connect(net, &sock, uri->host, uri->port)) {
    *result = NET_FETCH_CONNECTFAILED;
    return;
  }

  // initialize TLS session and associate a pointer to our state object with
  // its user-defined storage (helpful for accessing in callback funcs)

  // I tried to move this ugly blob of init into its own function but for some
  // reason gnutls kept segfaulting, so here we are
  gnutls_session_t session;
  gnutls_certificate_credentials_t cred;
  gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_NO_TICKETS);
  gnutls_session_set_ptr(session, s);
  gnutls_server_name_set(session, GNUTLS_NAME_DNS, uri->host,
                         strlen(uri->host));
  gnutls_certificate_allocate_credentials(&cred);
  gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
  gnutls_certificate_set_verify_function(cred, verify_certificate);
  gnutls_set_default_priority(session);
  set_tls_version(session);

  net->trusted = false;
  net->confirmed = false;

  if (!perform_handshake(net, sock, session)) {
    *result = NET_FETCH_TLSFAILED;
    goto close;
  }

  if (!net->trusted) {
    *result = NET_FETCH_CANCEL;
    goto goodbye;
  }

  if (net->confirmed) {
    goto goodbye;
  }

  // send the portion of the URI that the entirety of the URI, plus the
  // terminating CRLF
  size_t req_len;
  char* request = build_request(net, uri, &req_len);

  if (request == NULL) {
    net->fail("Ran out of memory while building the request string!");
    *result = NET_FETCH_NOMEM;
    goto close;
  }

  if (send_request(session, net, request, req_len)) {
    perform_download(session, net, s->page_contents);
  }

  free(request);

goodbye:
  gnutls_bye(session, GNUTLS_SHUT_RDWR);
  gnutls_certificate_free_credentials(cred);
  gnutls_deinit(session);

close:
  close(sock);
}

net_init_result_t init_network(network_t** n, status_callback_t status,
                               fail_callback_t fail,
                               confirm_callback_t confirm) {
  network_t* net = calloc(1, sizeof(network_t));
  *n = net;

  net->trusted = false;
  net->confirmed = false;
  net->status = status;
  net->fail = fail;
  net->confirm = confirm;

  if (!compile_uri_pattern(&net->uri_pattern)) {
    return NET_INIT_ERROR;
  }

  gnutls_global_init();

  return NET_INIT_OK;
}

void destroy_network(network_t* n) {
  if (n == NULL) {
    return;
  }

  if (n->last_uri != NULL) {
    free_uri(n->last_uri);
  }

  regfree(&n->uri_pattern);

  gnutls_global_deinit();

  free(n);
}

net_fetch_result_t reload_last(state_t* s) {
  net_fetch_result_t result = NET_FETCH_OK;
  network_t* net = s->network;

  if (s->network->last_uri == NULL) {
    return NET_FETCH_NORELOAD;
  }

  do {
    fetch_uri(s, net->last_uri, &result);
  } while (net->last_uri && net->last_uri);

  return result;
}

net_fetch_result_t fetch_content(state_t* s, const char* input) {
  net_fetch_result_t result = NET_FETCH_OK;
  network_t* net = s->network;

  uri_t* uri;
  if ((uri = build_uri_from_input(net, input, &result)) == NULL) {
    return result;
  }

  if (!copy_uri_as_last(net, uri, &result)) {
    goto finished;
  }

  do {
    fetch_uri(s, uri, &result);
  } while (net->confirmed && net->trusted);

finished:
  free_uri(uri);
  return result;
}

