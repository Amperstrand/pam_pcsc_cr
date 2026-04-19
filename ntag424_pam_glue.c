/*
 * ntag424_pam_glue.c — thin orchestration layer for NTAG424 PAM auth.
 *
 * Composes the verifier, reader, policy and replay modules into the
 * single call that pam_sm_authenticate invokes in NTAG424 mode.
 *
 * Nothing here logs URLs, p/c values, or key material.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#ifdef HAVE_SECURITY_PAM_APPL_H
# include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
# include <security/pam_modules.h>
#endif

#include "ntag424_pam_glue.h"
#include "ntag424_policy.h"
#include "ntag424_replay.h"
#include "ntag424_verifier.h"
#include "ntag424_reader.h"

/* =========================================================================
 * Status string
 * ====================================================================== */

const char *ntag424_auth_status_string(ntag424_auth_status_t status)
{
	switch (status) {
	case NTAG424_AUTH_OK:
		return "ok";
	case NTAG424_AUTH_ERR_ARGS:
		return "invalid argument";
	case NTAG424_AUTH_ERR_CONFIG:
		return "policy config error";
	case NTAG424_AUTH_ERR_DB:
		return "replay database error";
	case NTAG424_AUTH_ERR_READER:
		return "card read error";
	case NTAG424_AUTH_ERR_POLICY:
		return "no matching card entry for user";
	case NTAG424_AUTH_ERR_REPLAY:
		return "replay counter check failed";
	default:
		return "unknown error";
	}
}

/* =========================================================================
 * PAM conversation helper (only used when params->cue is set)
 * ====================================================================== */

static void pam_show_info(void *pamh, const char *text)
{
	struct pam_conv *conv;
	const struct pam_message msg = {
		.msg_style = PAM_TEXT_INFO,
		.msg = (char *)(uintptr_t)text
	};
	const struct pam_message *msgp = &msg;
	struct pam_response *resp = NULL;
	int rv;

	if (!pamh)
		return;

	rv = pam_get_item((pam_handle_t *)pamh, PAM_CONV,
			  (const void **)&conv);
	if (rv != PAM_SUCCESS || !conv || !conv->conv)
		return;

	conv->conv(1, &msgp, &resp, conv->appdata_ptr);
	if (resp) {
		free(resp->resp);
		free(resp);
	}
}

/* =========================================================================
 * Internal helper: format UID as 14-char uppercase hex
 * ====================================================================== */

static void uid_to_hex_upper(const uint8_t uid[NTAG424_UID_BYTES],
			     char buf[15])
{
	int i;
	for (i = 0; i < NTAG424_UID_BYTES; i++)
		snprintf(buf + i * 2, 3, "%02X", (unsigned)uid[i]);
}

/* =========================================================================
 * Core implementation (shared between run and run_with_transport)
 * ====================================================================== */

/*
 * run_internal — the actual orchestration logic.
 *
 * transport_override:
 *   - NULL  → use PC/SC backend
 *   - non-NULL → use the supplied transport directly (skip PC/SC)
 */
static ntag424_auth_status_t run_internal(
	const struct ntag424_auth_params *params,
	const ntag424_transport_t *transport_override)
{
	struct ntag424_policy     *policy  = NULL;
	struct ntag424_replay_db  *db      = NULL;
	struct ntag424_pcsc_ctx   *pcsc    = NULL;
	ntag424_transport_t        transport_copy;
	const ntag424_transport_t *transport;

	uint8_t  ndef_buf[NTAG424_READER_NDEF_MAX];
	size_t   ndef_len = 0;
	char     url[NTAG424_MAX_URL];
	char     uid_hex[15];

	ntag424_policy_status_t  prc;
	ntag424_replay_status_t  rrc;
	ntag424_reader_status_t  rdr_rc;
	ntag424_verify_status_t  vrc;
	ntag424_auth_status_t    result = NTAG424_AUTH_ERR_POLICY; /* fail-closed default */

	struct ntag424_verify_result       vresult;
	const struct ntag424_card_entry   *card = NULL;

	/* ── Validate required params ─────────────────────────────────── */
	if (!params ||
	    !params->username   || params->username[0]   == '\0' ||
	    !params->config_path || params->config_path[0] == '\0' ||
	    !params->db_path     || params->db_path[0]     == '\0') {
		return NTAG424_AUTH_ERR_ARGS;
	}

	/* ── Load policy config ───────────────────────────────────────── */
	prc = ntag424_policy_load(params->config_path, &policy);
	if (prc != NTAG424_POLICY_OK) {
		if (params->verbose)
			syslog(LOG_ERR, "ntag424: policy load: %s",
			       ntag424_policy_status_string(prc));
		return NTAG424_AUTH_ERR_CONFIG;
	}

	/* ── Open replay database ─────────────────────────────────────── */
	rrc = ntag424_replay_open(params->db_path, &db);
	if (rrc != NTAG424_REPLAY_OK) {
		if (params->verbose)
			syslog(LOG_ERR, "ntag424: replay open: %s",
			       ntag424_replay_status_string(rrc));
		result = NTAG424_AUTH_ERR_DB;
		goto out;
	}

	/* ── Acquire transport ────────────────────────────────────────── */
	if (transport_override) {
		transport = transport_override;
	} else {
		/* PC/SC path */
		rdr_rc = ntag424_pcsc_open(&pcsc);
		if (rdr_rc != NTAG424_READER_OK) {
			if (params->verbose)
				syslog(LOG_ERR, "ntag424: pcsc open: %s",
				       ntag424_reader_status_string(rdr_rc));
			result = NTAG424_AUTH_ERR_READER;
			goto out;
		}

		rdr_rc = ntag424_pcsc_select_reader(pcsc, params->reader_substr);
		if (rdr_rc != NTAG424_READER_OK) {
			if (params->verbose)
				syslog(LOG_ERR, "ntag424: select reader: %s",
				       ntag424_reader_status_string(rdr_rc));
			result = NTAG424_AUTH_ERR_READER;
			goto out;
		}

		if (params->verbose)
			syslog(LOG_DEBUG, "ntag424: reader: %s",
			       ntag424_pcsc_reader_name(pcsc)
			       ? ntag424_pcsc_reader_name(pcsc) : "(unknown)");

		if (params->cue)
			pam_show_info(params->pamh,
				      "Tap your NFC card on the reader...");

		if (params->timeout_ms > 0)
			rdr_rc = ntag424_pcsc_wait_and_connect(pcsc,
								params->timeout_ms);
		else
			rdr_rc = ntag424_pcsc_connect(pcsc);
		if (rdr_rc != NTAG424_READER_OK) {
			if (params->verbose)
				syslog(LOG_ERR, "ntag424: connect: %s",
				       ntag424_reader_status_string(rdr_rc));
			result = NTAG424_AUTH_ERR_READER;
			goto out;
		}

		rdr_rc = ntag424_pcsc_get_transport(pcsc, &transport_copy);
		if (rdr_rc != NTAG424_READER_OK) {
			if (params->verbose)
				syslog(LOG_ERR, "ntag424: get transport: %s",
				       ntag424_reader_status_string(rdr_rc));
			result = NTAG424_AUTH_ERR_READER;
			goto out;
		}
		transport = &transport_copy;
	}

	/* ── Read NDEF ────────────────────────────────────────────────── */
	rdr_rc = ntag424_read_ndef(transport, ndef_buf, sizeof(ndef_buf), &ndef_len);
	if (rdr_rc != NTAG424_READER_OK) {
		if (params->verbose)
			syslog(LOG_ERR, "ntag424: read ndef: %s",
			       ntag424_reader_status_string(rdr_rc));
		result = NTAG424_AUTH_ERR_READER;
		goto out;
	}

	/* ── Extract URL from NDEF ────────────────────────────────────── */
	vrc = ntag424_extract_url_from_ndef(ndef_buf, ndef_len,
					    url, sizeof(url));
	if (vrc != NTAG424_VERIFY_OK) {
		if (params->verbose)
			syslog(LOG_ERR, "ntag424: url extraction failed");
		result = NTAG424_AUTH_ERR_READER;
		goto out;
	}

	/* ── Verify URL against policy ────────────────────────────────── */
	memset(&vresult, 0, sizeof(vresult));
	prc = ntag424_policy_try_verify(policy, params->username,
					url, &vresult, &card);
	if (prc != NTAG424_POLICY_OK) {
		if (params->verbose)
			syslog(LOG_ERR, "ntag424: policy check: %s",
			       ntag424_policy_status_string(prc));
		result = NTAG424_AUTH_ERR_POLICY;
		goto out;
	}

	/* ── Replay check and update ──────────────────────────────────── */
	uid_to_hex_upper(vresult.uid, uid_hex);

	rrc = ntag424_replay_check_and_update(db, uid_hex,
					      vresult.counter_value);
	if (rrc != NTAG424_REPLAY_OK) {
		if (params->verbose)
			syslog(LOG_ERR, "ntag424: replay check: %s",
			       ntag424_replay_status_string(rrc));
		result = NTAG424_AUTH_ERR_REPLAY;
		goto out;
	}

	if (params->verbose)
		syslog(LOG_INFO, "ntag424: authenticated card [%s] for user [%s]",
		       card->card_id, params->username);

	if (params->cue && params->pamh) {
		char info[256];
		snprintf(info, sizeof(info),
			 "Card authenticated: %s  counter=%u  uid=%s",
			 card->card_id, vresult.counter_value, uid_hex);
		pam_show_info(params->pamh, info);
	}

	result = NTAG424_AUTH_OK;

out:
	if (pcsc)
		ntag424_pcsc_close(pcsc);
	ntag424_replay_close(db);
	ntag424_policy_free(policy);
	return result;
}

/* =========================================================================
 * Public entry points
 * ====================================================================== */

ntag424_auth_status_t ntag424_auth_run(
	const struct ntag424_auth_params *params)
{
	return run_internal(params, NULL);
}

ntag424_auth_status_t ntag424_auth_run_with_transport(
	const struct ntag424_auth_params *params,
	const ntag424_transport_t *transport)
{
	if (!transport)
		return NTAG424_AUTH_ERR_ARGS;
	return run_internal(params, transport);
}
