#include "../fuzzer.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerRunDriver(
    int *argc, char ***argv,
    int (*user_callback)(const uint8_t *data, size_t size)) {
  (void)argc;
  (void)argv;
  (void)user_callback;
  return 0;
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
  return 0;
}
