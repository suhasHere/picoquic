/*
 * Semi-Reliable QUIC Streams implementation.
 *
 * Provides deadline-based retransmission for QUIC streams. Each message
 * written to a semi-reliable stream has a lifetime. Lost packets are
 * retransmitted only while the deadline hasn't passed. Expired messages
 * generate STREAM_SKIP frames that advance the receiver past the gap.
 *
 * Key design principles:
 * - Wire compatible: uses standard STREAM frames for data
 * - Extension frames (STREAM_SKIP, STREAM_LIFETIME) are in private use space
 * - Backward compatible: endpoints that don't support it get fully reliable behavior
 * - Zero overhead when not used: semi-reliable state is only allocated on opt-in
 */

#include "picoquic_internal.h"
#include "semi_reliable.h"
#include <stdlib.h>
#include <string.h>

/* ========================================================================
 * Message list management
 * ======================================================================== */

static picoquic_stream_message_t* alloc_message(void)
{
    picoquic_stream_message_t* msg = (picoquic_stream_message_t*)malloc(sizeof(picoquic_stream_message_t));
    if (msg) {
        memset(msg, 0, sizeof(*msg));
    }
    return msg;
}

static void free_message(picoquic_stream_message_t* msg)
{
    free(msg);
}

static void append_message(picoquic_semi_reliable_ctx_t* ctx, picoquic_stream_message_t* msg)
{
    msg->next = NULL;
    msg->prev = ctx->tail;
    if (ctx->tail) {
        ctx->tail->next = msg;
    } else {
        ctx->messages = msg;
    }
    ctx->tail = msg;
}

static void remove_message(picoquic_semi_reliable_ctx_t* ctx, picoquic_stream_message_t* msg)
{
    if (msg->prev) {
        msg->prev->next = msg->next;
    } else {
        ctx->messages = msg->next;
    }
    if (msg->next) {
        msg->next->prev = msg->prev;
    } else {
        ctx->tail = msg->prev;
    }
    free_message(msg);
}

/* ========================================================================
 * Stream semi-reliable context management
 * ======================================================================== */

void picoquic_stream_set_semi_reliable(
    picoquic_cnx_t* cnx,
    uint64_t stream_id,
    uint64_t default_lifetime_us)
{
    picoquic_stream_head_t* stream;

    if (cnx == NULL) return;

    stream = picoquic_find_stream(cnx, stream_id);
    if (stream == NULL) return;

    if (stream->semi_reliable == NULL) {
        stream->semi_reliable = (picoquic_semi_reliable_ctx_t*)
            malloc(sizeof(picoquic_semi_reliable_ctx_t));
        if (stream->semi_reliable == NULL) return;
        memset(stream->semi_reliable, 0, sizeof(picoquic_semi_reliable_ctx_t));
    }

    stream->semi_reliable->enabled = 1;
    stream->semi_reliable->default_lifetime_us = default_lifetime_us;
}

/* ========================================================================
 * Message write with lifetime
 * ======================================================================== */

int picoquic_stream_write_message(
    picoquic_cnx_t* cnx,
    uint64_t stream_id,
    const uint8_t* data, size_t length,
    uint64_t lifetime_us,
    uint8_t priority,
    uint64_t depends_on)
{
    picoquic_stream_head_t* stream;
    picoquic_stream_message_t* msg;

    if (cnx == NULL || data == NULL || length == 0) return -1;

    stream = picoquic_find_stream(cnx, stream_id);
    if (stream == NULL) return -1;

    /* Record message boundary and deadline */
    if (stream->semi_reliable != NULL && stream->semi_reliable->enabled) {
        msg = alloc_message();
        if (msg == NULL) return -1;

        msg->offset = stream->sent_offset;
        msg->length = length;
        msg->send_time = picoquic_current_time();
        msg->lifetime_us = lifetime_us;
        msg->priority = priority;
        msg->depends_on = depends_on;

        append_message(stream->semi_reliable, msg);
        stream->semi_reliable->messages_sent++;
    }

    /* Write data to stream via standard path */
    picoquic_add_to_stream(cnx, stream_id, data, length, 0);

    return 0;
}

/* ========================================================================
 * Expiry check — called from retransmit path
 * ======================================================================== */

/* Cascade skip: when a message is skipped, skip all dependents too */
static void cascade_skip(picoquic_semi_reliable_ctx_t* ctx,
                         uint64_t skipped_offset)
{
    picoquic_stream_message_t* msg = ctx->messages;
    while (msg != NULL) {
        picoquic_stream_message_t* next = msg->next;
        if (!msg->skipped && msg->depends_on == skipped_offset) {
            msg->skipped = 1;
            ctx->messages_skipped++;
            ctx->bytes_skipped += msg->length;
            /* Recursively cascade */
            cascade_skip(ctx, msg->offset);
        }
        msg = next;
    }
}

int picoquic_semi_reliable_check_expiry(
    picoquic_cnx_t* cnx,
    uint64_t stream_id,
    uint64_t current_time)
{
    picoquic_stream_head_t* stream;
    picoquic_semi_reliable_ctx_t* ctx;
    picoquic_stream_message_t* msg;
    int skipped_count = 0;

    if (cnx == NULL) return 0;

    stream = picoquic_find_stream(cnx, stream_id);
    if (stream == NULL) return 0;

    ctx = stream->semi_reliable;
    if (ctx == NULL || !ctx->enabled) return 0;

    msg = ctx->messages;
    while (msg != NULL) {
        picoquic_stream_message_t* next = msg->next;

        if (msg->skipped) {
            msg = next;
            continue;
        }

        /* Priority 0 = must deliver, never skip */
        if (msg->priority == 0) {
            msg = next;
            continue;
        }

        /* Check deadline */
        if (msg->lifetime_us > 0 &&
            current_time > msg->send_time + msg->lifetime_us) {
            msg->skipped = 1;
            ctx->messages_skipped++;
            ctx->bytes_skipped += msg->length;
            skipped_count++;

            /* Cascade: skip dependent messages too */
            cascade_skip(ctx, msg->offset);
        }

        msg = next;
    }

    return skipped_count;
}

/* ========================================================================
 * STREAM_SKIP frame encoding/decoding
 * ======================================================================== */

uint8_t* picoquic_format_stream_skip(
    uint8_t* bytes, const uint8_t* bytes_max,
    uint64_t stream_id, uint64_t offset, uint64_t length)
{
    /* Frame type */
    if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max,
        PICOQUIC_FRAME_TYPE_STREAM_SKIP)) == NULL) return NULL;
    /* Stream ID */
    if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max,
        stream_id)) == NULL) return NULL;
    /* Offset */
    if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max,
        offset)) == NULL) return NULL;
    /* Length */
    if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max,
        length)) == NULL) return NULL;

    return bytes;
}

int picoquic_process_stream_skip(
    picoquic_cnx_t* cnx,
    const uint8_t* bytes, size_t bytes_max,
    size_t* consumed)
{
    uint64_t stream_id, offset, length;
    const uint8_t* p = bytes;
    const uint8_t* p_end = bytes + bytes_max;
    picoquic_stream_head_t* stream;

    /* Decode stream_id, offset, length */
    p = picoquic_frames_varint_decode(p, p_end, &stream_id);
    if (p == NULL) return -1;
    p = picoquic_frames_varint_decode(p, p_end, &offset);
    if (p == NULL) return -1;
    p = picoquic_frames_varint_decode(p, p_end, &length);
    if (p == NULL) return -1;

    *consumed = p - bytes;

    /* Find the stream and advance past the skipped region */
    stream = picoquic_find_stream(cnx, stream_id);
    if (stream == NULL) return 0;  /* Stream doesn't exist, ignore */

    /* Advance the consumed offset past the skipped region */
    uint64_t skip_end = offset + length;
    if (skip_end > stream->consumed_offset) {
        /* Release flow control credits for skipped bytes */
        uint64_t delta = skip_end - stream->consumed_offset;
        stream->consumed_offset = skip_end;

        /* Update connection-level flow control */
        cnx->data_received += delta;

        /* Notify application that data was skipped */
        if (cnx->callback_fn) {
            cnx->callback_fn(cnx, stream_id, NULL, (size_t)length,
                picoquic_callback_stream_gap, cnx->callback_ctx, NULL);
        }
    }

    return 0;
}

/* ========================================================================
 * STREAM_SKIP_REQUEST frame encoding/decoding
 * ======================================================================== */

uint8_t* picoquic_format_stream_skip_request(
    uint8_t* bytes, const uint8_t* bytes_max,
    uint64_t stream_id, uint64_t skip_until_offset)
{
    if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max,
        PICOQUIC_FRAME_TYPE_STREAM_SKIP_REQ)) == NULL) return NULL;
    if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max,
        stream_id)) == NULL) return NULL;
    if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max,
        skip_until_offset)) == NULL) return NULL;
    return bytes;
}

int picoquic_process_stream_skip_request(
    picoquic_cnx_t* cnx,
    const uint8_t* bytes, size_t bytes_max,
    size_t* consumed)
{
    uint64_t stream_id, skip_until;
    const uint8_t* p = bytes;
    const uint8_t* p_end = bytes + bytes_max;
    picoquic_stream_head_t* stream;
    picoquic_semi_reliable_ctx_t* ctx;

    p = picoquic_frames_varint_decode(p, p_end, &stream_id);
    if (p == NULL) return -1;
    p = picoquic_frames_varint_decode(p, p_end, &skip_until);
    if (p == NULL) return -1;

    *consumed = p - bytes;

    /* Find stream and mark all messages below skip_until as skipped */
    stream = picoquic_find_stream(cnx, stream_id);
    if (stream == NULL) return 0;

    ctx = stream->semi_reliable;
    if (ctx == NULL) return 0;

    picoquic_stream_message_t* msg = ctx->messages;
    while (msg != NULL) {
        if (!msg->skipped && msg->offset + msg->length <= skip_until) {
            msg->skipped = 1;
            ctx->messages_skipped++;
            ctx->bytes_skipped += msg->length;
        }
        msg = msg->next;
    }

    return 0;
}

/* ========================================================================
 * Cleanup
 * ======================================================================== */

void picoquic_semi_reliable_free(picoquic_semi_reliable_ctx_t* ctx)
{
    if (ctx == NULL) return;

    picoquic_stream_message_t* msg = ctx->messages;
    while (msg != NULL) {
        picoquic_stream_message_t* next = msg->next;
        free_message(msg);
        msg = next;
    }

    free(ctx);
}

/* ========================================================================
 * Integration point: should this packet be retransmitted?
 *
 * Called from picoquic_retransmit_needed() for packets containing
 * semi-reliable stream data. Returns 1 if the packet should be skipped
 * (not retransmitted).
 * ======================================================================== */

int picoquic_semi_reliable_should_skip_retransmit(
    picoquic_cnx_t* cnx,
    uint64_t stream_id,
    uint64_t offset,
    size_t length,
    uint64_t current_time)
{
    picoquic_stream_head_t* stream;
    picoquic_semi_reliable_ctx_t* ctx;
    picoquic_stream_message_t* msg;

    if (cnx == NULL) return 0;

    stream = picoquic_find_stream(cnx, stream_id);
    if (stream == NULL) return 0;

    ctx = stream->semi_reliable;
    if (ctx == NULL || !ctx->enabled) return 0;

    /* Check if any message covering this offset range has been skipped */
    msg = ctx->messages;
    while (msg != NULL) {
        /* Does this message overlap with the retransmit range? */
        if (msg->offset < offset + length && msg->offset + msg->length > offset) {
            if (msg->skipped) {
                return 1;  /* Already marked as skipped */
            }
            /* Check if it should be skipped now */
            if (msg->priority > 0 && msg->lifetime_us > 0 &&
                current_time > msg->send_time + msg->lifetime_us) {
                msg->skipped = 1;
                ctx->messages_skipped++;
                ctx->bytes_skipped += msg->length;
                cascade_skip(ctx, msg->offset);
                return 1;
            }
        }
        msg = msg->next;
    }

    return 0;
}
