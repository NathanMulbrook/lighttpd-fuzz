#include "fuzzer.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_PORT 5601
#define PACKET_DELAY_US 1000
#define FRAGMENT_DELAY_US 100
#define RESPONSE_TIMEOUT_MS 250
#define FINAL_RESPONSE_TIMEOUT_MS 25
#define ITERATION_SETTLE_DELAY_US 20000
#define POST_CLOSE_SETTLE_DELAY_US 2000

extern int LLVMFuzzerRunDriver(
    int *argc, char ***argv,
    int (*user_callback)(const uint8_t *data, size_t size));

static int target_port = DEFAULT_PORT;
static int hap_proxy_protocol;
static const char *test_case_log;
static uint64_t test_case_sequence;
static pthread_once_t fuzzer_once = PTHREAD_ONCE_INIT;

static int configuredPort(void) {
  const char *value = getenv("LIGHTTPD_FUZZ_PORT");
  if (value == NULL || *value == '\0') {
    return DEFAULT_PORT;
  }

  char *end = NULL;
  errno = 0;
  long port = strtol(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || port < 1 ||
      port > 65535) {
    fprintf(stderr, "Ignoring invalid LIGHTTPD_FUZZ_PORT: %s\n", value);
    return DEFAULT_PORT;
  }
  return (int)port;
}

static int configuredBoolean(const char *name) {
  const char *value = getenv(name);
  return value != NULL && *value != '\0' && strcmp(value, "0") != 0;
}

static void sleepMicroseconds(long delay_us) {
  struct timespec delay = {
      .tv_sec = delay_us / 1000000,
      .tv_nsec = (delay_us % 1000000) * 1000,
  };
  while (nanosleep(&delay, &delay) == -1 && errno == EINTR) {
  }
}

static int connectTarget(void) {
  struct sockaddr_in address;
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_port = htons((uint16_t)target_port);
  if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1) {
    return -1;
  }

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1) {
    return -1;
  }

  int one = 1;
  (void)setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  if (connect(sockfd, (struct sockaddr *)&address, sizeof(address)) == -1) {
    close(sockfd);
    return -1;
  }
  return sockfd;
}

int fuzzValidMultipacketData(const uint8_t *data, size_t size) {
  size_t offset = 0;
  size_t packet_count = 0;

  while (offset < size) {
    if (size - offset < 2) {
      return 0;
    }
    size_t packet_size = ((size_t)data[offset] << 8) | data[offset + 1];
    offset += 2;
    if (packet_size == 0 || packet_size > size - offset) {
      return 0;
    }
    offset += packet_size;
    if (++packet_count > FUZZ_MAX_PACKET_COUNT) {
      return 0;
    }
  }

  return packet_count > 0;
}

static int sendAll(int sockfd, const uint8_t *data, size_t size) {
  size_t sent = 0;
  while (sent < size) {
    ssize_t result = send(sockfd, data + sent, size - sent, MSG_NOSIGNAL);
    if (result > 0) {
      sent += (size_t)result;
    } else if (result == -1 && errno == EINTR) {
      continue;
    } else {
      return -1;
    }
  }
  return 0;
}

static int sendPacket(int sockfd, const uint8_t *data, size_t size,
                      int fragmented) {
  if (!fragmented || size < 2) {
    return sendAll(sockfd, data, size);
  }

  size_t split = size / 2;
  if (sendAll(sockfd, data, split) == -1) {
    return -1;
  }
  usleep(FRAGMENT_DELAY_US);
  return sendAll(sockfd, data + split, size - split);
}

static int readSomeResponse(int sockfd, int timeout_ms) {
  struct pollfd event = {.fd = sockfd, .events = POLLIN};
  int result;
  do {
    result = poll(&event, 1, timeout_ms);
  } while (result == -1 && errno == EINTR);

  if (result <= 0 || !(event.revents & (POLLIN | POLLHUP))) {
    return -1;
  }

  uint8_t response[8192];
  do {
    result = (int)recv(sockfd, response, sizeof(response), 0);
  } while (result == -1 && errno == EINTR);
  return result > 0 ? 0 : -1;
}

static int sendMultipacketData(int sockfd, const uint8_t *data, size_t size,
                               int wait_for_response, int fragmented) {
  size_t offset = 0;
  while (offset < size) {
    size_t packet_size = ((size_t)data[offset] << 8) | data[offset + 1];
    offset += 2;
    if (sendPacket(sockfd, data + offset, packet_size, fragmented) == -1) {
      return -1;
    }
    offset += packet_size;

    if (offset < size) {
      if (wait_for_response) {
        if (readSomeResponse(sockfd, RESPONSE_TIMEOUT_MS) == -1) {
          return -1;
        }
      } else {
        usleep(PACKET_DELAY_US);
      }
    }
  }
  return 0;
}

static void logInput(const uint8_t *data, size_t size) {
  if (test_case_log == NULL || *test_case_log == '\0') {
    return;
  }

  FILE *output = fopen(test_case_log, "a");
  if (output == NULL) {
    return;
  }

  struct timeval now;
  gettimeofday(&now, NULL);
  fprintf(output, "%010ld:%06ld pid=%ld seq=%llu - ", (long)now.tv_sec,
          (long)now.tv_usec, (long)getpid(),
          (unsigned long long)++test_case_sequence);
  for (size_t i = 0; i < size; ++i) {
    fprintf(output, "0x%02x, ", data[i]);
  }
  fputc('\n', output);
  fclose(output);
}

static int fuzzServer(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }

  uint8_t flags = data[0];
  const uint8_t *payload = data + 1;
  size_t payload_size = size - 1;
  if ((flags & FUZZ_MULTIPACKET_FLAG) &&
      !fuzzValidMultipacketData(payload, payload_size)) {
    return 0;
  }

  int sockfd = connectTarget();
  if (sockfd == -1) {
    return 0;
  }

  /* Record the active input before target code can emit a diagnostic. */
  logInput(data, size);

  int send_result;
  if (flags & FUZZ_MULTIPACKET_FLAG) {
    send_result = sendMultipacketData(
        sockfd, payload, payload_size,
        (flags & FUZZ_WAIT_FOR_RESPONSE_FLAG) != 0,
        (flags & FUZZ_FRAGMENT_SEND_FLAG) != 0);
  } else {
    send_result = sendPacket(sockfd, payload, payload_size,
                             (flags & FUZZ_FRAGMENT_SEND_FLAG) != 0);
  }

  if (send_result == 0) {
    (void)readSomeResponse(sockfd, FINAL_RESPONSE_TIMEOUT_MS);
  }

  /*
   * lighttpd processes this socket on its event-loop thread.  Keep the
   * libFuzzer callback active while request work settles, then give EOF and
   * connection cleanup a separate grace period.  Without this fence, a fast
   * first response byte can let late coverage leak into the next input.
   */
  sleepMicroseconds(ITERATION_SETTLE_DELAY_US);
  close(sockfd);
  sleepMicroseconds(POST_CLOSE_SETTLE_DELAY_US);
  return 0;
}

static int checkServerUp(void) {
  static const uint8_t proxy_header[] = "PROXY UNKNOWN\r\n";
  static const uint8_t request[] =
      "GET /__fuzz_health HTTP/1.0\r\nConnection: close\r\n\r\n";
  int sockfd = connectTarget();
  if (sockfd == -1) {
    return 0;
  }

  int ready = 0;
  if ((!hap_proxy_protocol ||
       sendAll(sockfd, proxy_header, sizeof(proxy_header) - 1) == 0) &&
      sendAll(sockfd, request, sizeof(request) - 1) == 0) {
    struct pollfd event = {.fd = sockfd, .events = POLLIN};
    int result;
    do {
      result = poll(&event, 1, 500);
    } while (result == -1 && errno == EINTR);
    if (result > 0) {
      uint8_t response[16];
      ssize_t received = recv(sockfd, response, sizeof(response), 0);
      ready = received >= 5 && memcmp(response, "HTTP/", 5) == 0;
    }
  }
  close(sockfd);
  return ready;
}

static void *runFuzzer(void *unused) {
  (void)unused;
  target_port = configuredPort();
  hap_proxy_protocol = configuredBoolean("LIGHTTPD_FUZZ_HAP_PROXY");
  test_case_log = getenv("LIGHTTPD_FUZZ_LOG");

  for (unsigned int attempt = 1; !checkServerUp(); ++attempt) {
    if (attempt == 1 || attempt % 10 == 0) {
      fprintf(stderr, "Waiting for lighttpd on 127.0.0.1:%d (%u)\n",
              target_port, attempt);
    }
    sleep(1);
  }

  const char *corpus = getenv("LIGHTTPD_FUZZ_CORPUS");
  const char *artifacts = getenv("LIGHTTPD_FUZZ_ARTIFACT_PREFIX");
  if (corpus == NULL || *corpus == '\0') {
    corpus = "corpus";
  }
  if (artifacts == NULL || *artifacts == '\0') {
    artifacts = "./";
  }

  char artifact_arg[4096];
  if (snprintf(artifact_arg, sizeof(artifact_arg), "-artifact_prefix=%s",
               artifacts) >= (int)sizeof(artifact_arg)) {
    fprintf(stderr, "LIGHTTPD_FUZZ_ARTIFACT_PREFIX is too long\n");
    return NULL;
  }

  char *arguments[] = {
      (char *)"lighttpd-fuzzer", (char *)corpus,
      (char *)"-max_len=65000", (char *)"-detect_leaks=0",
      (char *)"-len_control=20", (char *)"-rss_limit_mb=4096",
      (char *)"-verbosity=1", artifact_arg, NULL};
  int argument_count = 8;
  char **argument_pointer = arguments;

  fprintf(stderr, "Starting embedded fuzzer for port %d\n", target_port);
  (void)LLVMFuzzerRunDriver(&argument_count, &argument_pointer, fuzzServer);
  return NULL;
}

static void startFuzzerThread(void) {
  pthread_t thread;
  int result = pthread_create(&thread, NULL, runFuzzer, NULL);
  if (result != 0) {
    fprintf(stderr, "Unable to create fuzzer thread: %s\n", strerror(result));
    return;
  }
  (void)pthread_detach(thread);
}

void launchFuzzer(void) { (void)pthread_once(&fuzzer_once, startFuzzerThread); }
