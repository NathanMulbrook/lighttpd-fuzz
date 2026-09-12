#ifndef LIGHTTPD_FUZZER_H
#define LIGHTTPD_FUZZER_H

#include <stddef.h>
#include <stdint.h>

#define FUZZ_FRAGMENT_SEND_FLAG 0x01
#define FUZZ_MULTIPACKET_FLAG 0x02
#define FUZZ_WAIT_FOR_RESPONSE_FLAG 0x04
#define FUZZ_MAX_PACKET_COUNT 64

int fuzzValidMultipacketData(const uint8_t *data, size_t size);
void launchFuzzer(void);

#endif
