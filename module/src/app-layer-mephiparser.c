/* Copyright (C) 2015-2020 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/*
 * TODO: Update \author in this file and app-layer-mephiparser.h.
 * TODO: Implement your app-layer logic with unit tests.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * MephiParser application layer detector and parser for learning and
 * mephiparser purposes.
 *
 * This mephiparser implements a simple application layer for something
 * like the echo protocol running on port 102
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"
#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"
#include "app-layer-mephiparser.h"

#include "util-unittest.h"
#include "util-validate.h"

/* The default port to probe for echo traffic if not provided in the
 * configuration file. */
#define MEPHIPARSER_DEFAULT_PORT "102"

/* The minimum size for a message. For some protocols this might
 * be the size of a header. */
#define MEPHIPARSER_MIN_FRAME_LEN 8

/* Enum of app-layer events for the protocol. Normally you might
 * have events for errors in parsing data, like unexpected data being
 * received. For mephiparser we'll make something up, and log an app-layer
 * level alert if an empty message is received.
 *
 * Example rule:
 *
 * alert mephiparser any any -> any any (msg:"SURICATA MephiParser empty message"; \
 *    app-layer-event:mephiparser.empty_message; sid:X; rev:Y;)
 */
enum {
    MEPHIPARSER_DECODER_EVENT_EMPTY_MESSAGE,
};

SCEnumCharMap mephiparser_decoder_event_table[] = {
    {"EMPTY_MESSAGE", MEPHIPARSER_DECODER_EVENT_EMPTY_MESSAGE},

    // event table must be NULL-terminated
    { NULL, -1 },
};

static MephiParserTransaction *MephiParserTxAlloc(MephiParserState *state)
{
    MephiParserTransaction *tx = SCCalloc(1, sizeof(MephiParserTransaction));
    if (unlikely(tx == NULL)) {
        return NULL;
    }

    /* Increment the transaction ID on the state each time one is
     * allocated. */
    tx->tx_id = state->transaction_max++;

    TAILQ_INSERT_TAIL(&state->tx_list, tx, next);

    return tx;
}

static void MephiParserTxFree(void *txv)
{
    MephiParserTransaction *tx = txv;

    if (tx->request_buffer != NULL) {
        SCFree(tx->request_buffer);
    }

    if (tx->response_buffer != NULL) {
        SCFree(tx->response_buffer);
    }

    AppLayerDecoderEventsFreeEvents(&tx->tx_data.events);

    SCFree(tx);
}

static void *MephiParserStateAlloc(void *orig_state, AppProto proto_orig)
{
    SCLogNotice("Allocating mephiparser state.");
    MephiParserState *state = SCCalloc(1, sizeof(MephiParserState));
    if (unlikely(state == NULL)) {
        return NULL;
    }
    TAILQ_INIT(&state->tx_list);
    return state;
}

static void MephiParserStateFree(void *state)
{
    MephiParserState *mephiparser_state = state;
    MephiParserTransaction *tx;
    SCLogNotice("Freeing mephiparser state.");
    while ((tx = TAILQ_FIRST(&mephiparser_state->tx_list)) != NULL) {
        TAILQ_REMOVE(&mephiparser_state->tx_list, tx, next);
        MephiParserTxFree(tx);
    }
    SCFree(mephiparser_state);
}

/**
 * \brief Callback from the application layer to have a transaction freed.
 *
 * \param state a void pointer to the MephiParserState object.
 * \param tx_id the transaction ID to free.
 */
static void MephiParserStateTxFree(void *statev, uint64_t tx_id)
{
    MephiParserState *state = statev;
    MephiParserTransaction *tx = NULL, *ttx;

    SCLogNotice("Freeing transaction %"PRIu64, tx_id);

    TAILQ_FOREACH_SAFE(tx, &state->tx_list, next, ttx) {

        /* Continue if this is not the transaction we are looking
         * for. */
        if (tx->tx_id != tx_id) {
            continue;
        }

        /* Remove and free the transaction. */
        TAILQ_REMOVE(&state->tx_list, tx, next);
        MephiParserTxFree(tx);
        return;
    }

    SCLogNotice("Transaction %"PRIu64" not found.", tx_id);
}

static int MephiParserStateGetEventInfo(const char *event_name, int *event_id,
    AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, mephiparser_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "mephiparser enum map table.",  event_name);
        /* This should be treated as fatal. */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static int MephiParserStateGetEventInfoById(int event_id, const char **event_name,
                                         AppLayerEventType *event_type)
{
    *event_name = SCMapEnumValueToName(event_id, mephiparser_decoder_event_table);
    if (*event_name == NULL) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%d\" not present in "
                   "mephiparser enum map table.",  event_id);
        /* This should be treated as fatal. */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

/**
 * \brief Probe the input to server to see if it looks like mephiparser.
 *
 * \retval ALPROTO_MEPHIPARSER if it looks like mephiparser,
 *     ALPROTO_FAILED, if it is clearly not ALPROTO_MEPHIPARSER,
 *     otherwise ALPROTO_UNKNOWN.
 */
static AppProto MephiParserProbingParserTs(Flow *f, uint8_t direction,
        const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{

    if(input_len > 4) {
            SCLogNotice("%02x:%02x:%02x:%02x", input[7], input[8], input[9], input[10]);
        }
    /* Very simple test - if there is input, this is mephiparser. */
     if (input_len >= MEPHIPARSER_MIN_FRAME_LEN && input[7] == 0x32 && input[9] == 0x00 && input[10] == 0x00) {
        SCLogNotice("Detected as ALPROTO_MEPHIPARSER.");
        SCLogNotice("To server : %d",input_len);
        if(input_len > 4) {
            SCLogNotice("%02x:%02x:%02x:%02x", input[7], input[8], input[9], input[10]);
        }
        return ALPROTO_MEPHIPARSER;
    }

    SCLogNotice("Protocol not detected as ALPROTO_MEPHIPARSER.");
    return ALPROTO_UNKNOWN;
}

/**
 * \brief Probe the input to client to see if it looks like mephiparser.
 *     MephiParserProbingParserTs can be used instead if the protocol
 *     is symmetric.
 *
 * \retval ALPROTO_MEPHIPARSER if it looks like mephiparser,
 *     ALPROTO_FAILED, if it is clearly not ALPROTO_MEPHIPARSER,
 *     otherwise ALPROTO_UNKNOWN.
 */
static AppProto MephiParserProbingParserTc(Flow *f, uint8_t direction,
        const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{

    if(input_len > 4) {
            SCLogNotice("%02x:%02x:%02x:%02x", input[7], input[8], input[9], input[10]);
        }
    /* Very simple test - if there is input, this is mephiparser. */
    if (input_len >= MEPHIPARSER_MIN_FRAME_LEN && input[7] == 0x32 && input[9] == 0x00 && input[10] == 0x00) {
        SCLogNotice("%d",input_len);
        SCLogNotice("Detected as ALPROTO_MEPHIPARSER.");
        return ALPROTO_MEPHIPARSER;
    }

    SCLogNotice("Protocol not detected as ALPROTO_MEPHIPARSER.");
    return ALPROTO_UNKNOWN;
}

static AppLayerResult MephiParserParseRequest(Flow *f, void *statev,
    AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len,
    void *local_data, const uint8_t flags)
{
    MephiParserState *state = statev;

    SCLogNotice("Parsing mephiparser request: len=%"PRIu32, input_len);

    if (input == NULL) {
        if (AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS)) {
            /* This is a signal that the stream is done. Do any
             * cleanup if needed. Usually nothing is required here. */
            SCReturnStruct(APP_LAYER_OK);
        } else if (flags & STREAM_GAP) {
            /* This is a signal that there has been a gap in the
             * stream. This only needs to be handled if gaps were
             * enabled during protocol registration. The input_len
             * contains the size of the gap. */
            SCReturnStruct(APP_LAYER_OK);
        }
        /* This should not happen. If input is NULL, one of the above should be
         * true. */
        DEBUG_VALIDATE_BUG_ON(true);
        SCReturnStruct(APP_LAYER_ERROR);
    }

    /* Normally you would parse out data here and store it in the
     * transaction object, but as this is echo, we'll just record the
     * request data. */

    /* Also, if this protocol may have a "protocol data unit" span
     * multiple chunks of data, which is always a possibility with
     * TCP, you may need to do some buffering here.
     *
     * For the sake of simplicity, buffering is left out here, but
     * even for an echo protocol we may want to buffer until a new
     * line is seen, assuming its text based.
     */

    /* Allocate a transaction.
     *
     * But note that if a "protocol data unit" is not received in one
     * chunk of data, and the buffering is done on the transaction, we
     * may need to look for the transaction that this newly received
     * data belongs to.
     */
    MephiParserTransaction *tx = MephiParserTxAlloc(state);
    if (unlikely(tx == NULL)) {
        SCLogNotice("Failed to allocate new MephiParser tx.");
        goto end;
    }
    SCLogNotice("Allocated MephiParser tx %"PRIu64".", tx->tx_id);

    /* Make a copy of the request. */
    tx->request_buffer = SCCalloc(1, input_len);
    if (unlikely(tx->request_buffer == NULL)) {
        goto end;
    }
    memcpy(tx->request_buffer, input, input_len);
    tx->request_buffer_len = input_len;

    /* Here we check for an empty message and create an app-layer
     * event. */
    if ((input_len == 1 && tx->request_buffer[0] == '\n') ||
        (input_len == 2 && tx->request_buffer[0] == '\r')) {
        SCLogNotice("Creating event for empty message.");
        AppLayerDecoderEventsSetEventRaw(&tx->tx_data.events, MEPHIPARSER_DECODER_EVENT_EMPTY_MESSAGE);
    }

end:
    SCReturnStruct(APP_LAYER_OK);
}

static AppLayerResult MephiParserParseResponse(Flow *f, void *statev, AppLayerParserState *pstate,
    const uint8_t *input, uint32_t input_len, void *local_data,
    const uint8_t flags)
{
    MephiParserState *state = statev;
    MephiParserTransaction *tx = NULL, *ttx;

    SCLogNotice("Parsing MephiParser response.");

    /* Likely connection closed, we can just return here. */
    if ((input == NULL || input_len == 0) &&
        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC)) {
        SCReturnStruct(APP_LAYER_OK);
    }

    /* Probably don't want to create a transaction in this case
     * either. */
    if (input == NULL || input_len == 0) {
        SCReturnStruct(APP_LAYER_OK);
    }

    /* Look up the existing transaction for this response. In the case
     * of echo, it will be the most recent transaction on the
     * MephiParserState object. */

    /* We should just grab the last transaction, but this is to
     * illustrate how you might traverse the transaction list to find
     * the transaction associated with this response. */
    TAILQ_FOREACH(ttx, &state->tx_list, next) {
        tx = ttx;
    }

    if (tx == NULL) {
        SCLogNotice("Failed to find transaction for response on state %p.",
            state);
        goto end;
    }

    SCLogNotice("Found transaction %"PRIu64" for response on state %p.",
        tx->tx_id, state);

    /* If the protocol requires multiple chunks of data to complete, you may
     * run into the case where you have existing response data.
     *
     * In this case, we just log that there is existing data and free it. But
     * you might want to realloc the buffer and append the data.
     */
    if (tx->response_buffer != NULL) {
        SCLogNotice("WARNING: Transaction already has response data, "
            "existing data will be overwritten.");
        SCFree(tx->response_buffer);
    }

    /* Make a copy of the response. */
    tx->response_buffer = SCCalloc(1, input_len);
    if (unlikely(tx->response_buffer == NULL)) {
        goto end;
    }
    memcpy(tx->response_buffer, input, input_len);
    tx->response_buffer_len = input_len;

    /* Set the response_done flag for transaction state checking in
     * MephiParserGetStateProgress(). */
    tx->response_done = 1;

end:
    SCReturnStruct(APP_LAYER_OK);
}

static uint64_t MephiParserGetTxCnt(void *statev)
{
    const MephiParserState *state = statev;
    SCLogNotice("Current tx count is %"PRIu64".", state->transaction_max);
    return state->transaction_max;
}

static void *MephiParserGetTx(void *statev, uint64_t tx_id)
{
    MephiParserState *state = statev;
    MephiParserTransaction *tx;

    SCLogNotice("Requested tx ID %"PRIu64".", tx_id);

    TAILQ_FOREACH(tx, &state->tx_list, next) {
        if (tx->tx_id == tx_id) {
            SCLogNotice("Transaction %"PRIu64" found, returning tx object %p.",
                tx_id, tx);
            return tx;
        }
    }

    SCLogNotice("Transaction ID %"PRIu64" not found.", tx_id);
    return NULL;
}

/**
 * \brief Return the state of a transaction in a given direction.
 *
 * In the case of the echo protocol, the existence of a transaction
 * means that the request is done. However, some protocols that may
 * need multiple chunks of data to complete the request may need more
 * than just the existence of a transaction for the request to be
 * considered complete.
 *
 * For the response to be considered done, the response for a request
 * needs to be seen. The response_done flag is set on response for
 * checking here.
 */
static int MephiParserGetStateProgress(void *txv, uint8_t direction)
{
    MephiParserTransaction *tx = txv;

    SCLogNotice("Transaction progress requested for tx ID %"PRIu64
        ", direction=0x%02x", tx->tx_id, direction);

    if (direction & STREAM_TOCLIENT && tx->response_done) {
        return 1;
    }
    else if (direction & STREAM_TOSERVER) {
        /* For the mephiparser, just the existence of the transaction means the
         * request is done. */
        return 1;
    }

    return 0;
}

/**
 * \brief retrieve the tx data used for logging, config, detection
 */
static AppLayerTxData *MephiParserGetTxData(void *vtx)
{
    MephiParserTransaction *tx = vtx;
    return &tx->tx_data;
}

void RegisterMephiParserParsers(void)
{
    const char *proto_name = "mephiparser";

    /* Check if MephiParser TCP detection is enabled. If it does not exist in
     * the configuration file then it will be disabled by default. */
    if (AppLayerProtoDetectConfProtoDetectionEnabledDefault("tcp", proto_name, false)) {

        SCLogDebug("MephiParser TCP protocol detection enabled.");

        AppLayerProtoDetectRegisterProtocol(ALPROTO_MEPHIPARSER, proto_name);

        if (RunmodeIsUnittests()) {

            SCLogNotice("Unittest mode, registering default configuration.");
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, MEPHIPARSER_DEFAULT_PORT,
                ALPROTO_MEPHIPARSER, 0, MEPHIPARSER_MIN_FRAME_LEN, STREAM_TOSERVER,
                MephiParserProbingParserTs, MephiParserProbingParserTc);

        }
        else {

            if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                    proto_name, ALPROTO_MEPHIPARSER, 0, MEPHIPARSER_MIN_FRAME_LEN,
                    MephiParserProbingParserTs, MephiParserProbingParserTc)) {
                SCLogDebug("No mephiparser app-layer configuration, enabling echo"
                           " detection TCP detection on port %s.",
                        MEPHIPARSER_DEFAULT_PORT);
                AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                    MEPHIPARSER_DEFAULT_PORT, ALPROTO_MEPHIPARSER, 0,
                    MEPHIPARSER_MIN_FRAME_LEN, STREAM_TOSERVER,
                    MephiParserProbingParserTs, MephiParserProbingParserTc);
            }

        }

    }

    else {
        SCLogDebug("Protocol detector and parser disabled for MephiParser.");
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {

        SCLogNotice("Registering MephiParser protocol parser.");

        /* Register functions for state allocation and freeing. A
         * state is allocated for every new MephiParser flow. */
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_MEPHIPARSER,
            MephiParserStateAlloc, MephiParserStateFree);

        /* Register request parser for parsing frame from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_MEPHIPARSER,
            STREAM_TOSERVER, MephiParserParseRequest);

        /* Register response parser for parsing frames from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_MEPHIPARSER,
            STREAM_TOCLIENT, MephiParserParseResponse);

        /* Register a function to be called by the application layer
         * when a transaction is to be freed. */
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_MEPHIPARSER,
            MephiParserStateTxFree);

        /* Register a function to return the current transaction count. */
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_MEPHIPARSER,
            MephiParserGetTxCnt);

        /* Transaction handling. */
        AppLayerParserRegisterStateProgressCompletionStatus(ALPROTO_MEPHIPARSER, 1, 1);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP,
            ALPROTO_MEPHIPARSER, MephiParserGetStateProgress);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_MEPHIPARSER,
            MephiParserGetTx);
        AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_MEPHIPARSER,
            MephiParserGetTxData);

        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_MEPHIPARSER,
            MephiParserStateGetEventInfo);
        AppLayerParserRegisterGetEventInfoById(IPPROTO_TCP, ALPROTO_MEPHIPARSER,
            MephiParserStateGetEventInfoById);

        /* Leave this is if your parser can handle gaps, otherwise
         * remove. */
        AppLayerParserRegisterOptionFlags(IPPROTO_TCP, ALPROTO_MEPHIPARSER,
            APP_LAYER_PARSER_OPT_ACCEPT_GAPS);
    }
    else {
        SCLogDebug("MephiParser protocol parsing disabled.");
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_MEPHIPARSER,
        MephiParserParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void MephiParserParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}
