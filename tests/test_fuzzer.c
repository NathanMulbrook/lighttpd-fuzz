#include "../fuzzer.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t sync_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t sync_condition = PTHREAD_COND_INITIALIZER;
static int delayed_work_done;
static int connection_cleanup_done;
static int callback_done;
static int callback_synchronized;
static char test_log_path[] = "/tmp/lighttpd-fuzzer-log-XXXXXX";

static int64_t monotonicMicroseconds(void) {
  struct timespec now;
  assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
  return (int64_t)now.tv_sec * 1000000 + now.tv_nsec / 1000;
}

static void sleepMicroseconds(long delay_us) {
  struct timespec delay = {
      .tv_sec = delay_us / 1000000,
      .tv_nsec = (delay_us % 1000000) * 1000,
  };
  while (nanosleep(&delay, &delay) == -1 && errno == EINTR) {
  }
}

static int acceptClient(int listener) {
  int client;
  do {
    client = accept(listener, NULL, NULL);
  } while (client == -1 && errno == EINTR);
  assert(client != -1);
  return client;
}

static void receiveRequest(int client) {
  char request[4096];
  ssize_t received;
  do {
    received = recv(client, request, sizeof(request), 0);
  } while (received == -1 && errno == EINTR);
  assert(received > 0);
}

static void *runSynchronizationServer(void *argument) {
  int listener = *(int *)argument;

  int client = acceptClient(listener);
  receiveRequest(client);
  static const char health_response[] =
      "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
  assert(send(client, health_response, sizeof(health_response) - 1, 0) > 0);
  close(client);

  client = acceptClient(listener);
  receiveRequest(client);
  FILE *test_log = fopen(test_log_path, "r");
  assert(test_log != NULL);
  char log_line[256];
  assert(fgets(log_line, sizeof(log_line), test_log) != NULL);
  assert(strstr(log_line, " pid=") != NULL);
  assert(strstr(log_line, " seq=1 - 0x00,") != NULL);
  fclose(test_log);
  assert(send(client, "x", 1, 0) == 1);

  /* This work would be attributed to the next input without a settle fence. */
  sleepMicroseconds(5000);
  pthread_mutex_lock(&sync_mutex);
  delayed_work_done = 1;
  pthread_mutex_unlock(&sync_mutex);

  char byte;
  ssize_t received;
  do {
    received = recv(client, &byte, 1, 0);
  } while (received == -1 && errno == EINTR);
  assert(received == 0);

  pthread_mutex_lock(&sync_mutex);
  connection_cleanup_done = 1;
  pthread_mutex_unlock(&sync_mutex);
  close(client);
  close(listener);
  return NULL;
}

int LLVMFuzzerRunDriver(
    int *argc, char ***argv,
    int (*user_callback)(const uint8_t *data, size_t size)) {
  (void)argc;
  (void)argv;

  static const uint8_t input[] = {
      0x00, 'G', 'E', 'T', ' ', '/', ' ', 'H', 'T', 'T', 'P', '/', '1',
      '.',  '0',  '\r', '\n', 'C', 'o', 'n', 'n', 'e', 'c', 't', 'i',
      'o',  'n',  ':',  ' ', 'c', 'l', 'o', 's', 'e', '\r', '\n', '\r',
      '\n'};
  int64_t started = monotonicMicroseconds();
  assert(user_callback(input, sizeof(input)) == 0);
  int64_t elapsed = monotonicMicroseconds() - started;

  pthread_mutex_lock(&sync_mutex);
  callback_synchronized = delayed_work_done && connection_cleanup_done &&
                          elapsed >= 20000;
  callback_done = 1;
  pthread_cond_signal(&sync_condition);
  pthread_mutex_unlock(&sync_mutex);
  return 0;
}

static void testIterationSynchronization(void) {
  int listener = socket(AF_INET, SOCK_STREAM, 0);
  assert(listener != -1);

  int one = 1;
  assert(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) ==
         0);
  struct sockaddr_in address;
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  assert(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
  assert(listen(listener, 2) == 0);

  socklen_t address_size = sizeof(address);
  assert(getsockname(listener, (struct sockaddr *)&address, &address_size) ==
         0);
  char port[16];
  assert(snprintf(port, sizeof(port), "%u", ntohs(address.sin_port)) > 0);
  assert(setenv("LIGHTTPD_FUZZ_PORT", port, 1) == 0);
  int test_log = mkstemp(test_log_path);
  assert(test_log != -1);
  close(test_log);
  assert(setenv("LIGHTTPD_FUZZ_LOG", test_log_path, 1) == 0);

  pthread_t server_thread;
  assert(pthread_create(&server_thread, NULL, runSynchronizationServer,
                        &listener) == 0);
  launchFuzzer();

  struct timespec deadline;
  assert(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
  deadline.tv_sec += 5;
  pthread_mutex_lock(&sync_mutex);
  while (!callback_done) {
    int result =
        pthread_cond_timedwait(&sync_condition, &sync_mutex, &deadline);
    assert(result == 0);
  }
  assert(callback_synchronized);
  pthread_mutex_unlock(&sync_mutex);
  assert(pthread_join(server_thread, NULL) == 0);
  assert(unlink(test_log_path) == 0);
}

int main(void) {
  const uint8_t one[] = {0x00, 0x01, 'x'};
  const uint8_t two[] = {0x00, 0x01, 'x', 0x00, 0x02, 'y', 'z'};
  const uint8_t truncated_length[] = {0x00};
  const uint8_t zero_length[] = {0x00, 0x00};
  const uint8_t truncated_packet[] = {0x00, 0x02, 'x'};

  assert(fuzzValidMultipacketData(one, sizeof(one)));
  assert(fuzzValidMultipacketData(two, sizeof(two)));
  assert(!fuzzValidMultipacketData(NULL, 0));
  assert(!fuzzValidMultipacketData(truncated_length, sizeof(truncated_length)));
  assert(!fuzzValidMultipacketData(zero_length, sizeof(zero_length)));
  assert(!fuzzValidMultipacketData(truncated_packet, sizeof(truncated_packet)));

  uint8_t too_many[(FUZZ_MAX_PACKET_COUNT + 1) * 3];
  for (size_t i = 0; i < FUZZ_MAX_PACKET_COUNT + 1; ++i) {
    too_many[i * 3] = 0;
    too_many[i * 3 + 1] = 1;
    too_many[i * 3 + 2] = (uint8_t)i;
  }
  assert(!fuzzValidMultipacketData(too_many, sizeof(too_many)));
  testIterationSynchronization();
  return 0;
}
