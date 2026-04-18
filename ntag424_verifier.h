#ifndef _NTAG424_VERIFIER_H
#define _NTAG424_VERIFIER_H

#include <stdint.h>
#include <stddef.h>

#define NTAG424_KEY_BYTES 16
#define NTAG424_UID_BYTES 7
#define NTAG424_COUNTER_BYTES 3
#define NTAG424_P_HEX_LEN 32
#define NTAG424_C_HEX_LEN 16

typedef enum {
	NTAG424_VERIFY_OK = 0,
	NTAG424_VERIFY_ERR_INVALID_ARGUMENT,
	NTAG424_VERIFY_ERR_PARAM_PARSE,
	NTAG424_VERIFY_ERR_P_HEX,
	NTAG424_VERIFY_ERR_C_HEX,
	NTAG424_VERIFY_ERR_CRYPTO,
	NTAG424_VERIFY_ERR_PICC_TAG,
	NTAG424_VERIFY_ERR_CMAC_MISMATCH
} ntag424_verify_status_t;

struct ntag424_verify_result {
	ntag424_verify_status_t status;
	uint8_t uid[NTAG424_UID_BYTES];
	uint8_t counter_be[NTAG424_COUNTER_BYTES];
	uint32_t counter_value;
};

ntag424_verify_status_t ntag424_extract_p_c(const char *input,
	char *p_hex, size_t p_hex_size,
	char *c_hex, size_t c_hex_size);

ntag424_verify_status_t ntag424_verify_p_c(
	const uint8_t k1[NTAG424_KEY_BYTES],
	const uint8_t k2[NTAG424_KEY_BYTES],
	const char *p_hex,
	const char *c_hex,
	struct ntag424_verify_result *out);

const char *ntag424_verify_status_string(ntag424_verify_status_t status);

#endif
