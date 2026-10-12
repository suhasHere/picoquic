/*
 * Semi-Reliable QUIC Streams: deadline-based retransmission.
 *
 * Each message on a semi-reliable stream has a lifetime. Lost packets
 * are retransmitted only if the deadline hasn't passed. Expired messages
 * generate STREAM_SKIP frames that tell the receiver to advance past
 * the gap without waiting for retransmission.
 *
 * See: perf-analysis/semi_reliable_streams_design.md
 */

#ifndef SEMI_RELIABLE_H
#define SEMI_RELIABLE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Frame types for semi-reliable streams (private use space) */
#define PICOQUIC_FRAME_TYPE_STREAM_LIFETIME  0xBF02
#define PICOQUIC_FRAME_TYPE_STREAM_SKIP      0xBF03
#define PICOQUIC_FRAME_TYPE_STREAM_SKIP_REQ  0xBF04
#define PICOQUIC_FRAME_TYPE_STREAM_QUALITY   0xBF05

/* Transport parameter ID */
#define PICOQUIC_TP_SEMI_RELIABLE_STREAMS    0xBF01

/* Message entry in per-stream message list */
typedef struct st_picoquic_stream_message {
    uint64_t offset;            /* Start offset in stream byte space */
    uint64_t length;            /* Message length in bytes */
    uint64_t send_time;         /* When first packet was sent */
    uint64_t lifetime_us;       /* Microseconds until expiry (0 = fully reliable) */
    uint64_t depends_on;        /* Offset of dependency (0 = none) */
    uint8_t  priority;          /* 0 = must deliver, 255 = best effort */
    uint8_t  skipped;           /* 1 if STREAM_SKIP was sent for this message */
    uint8_t  skip_sent;         /* 1 if the STREAM_SKIP frame has been queued */
    struct st_picoquic_stream_message* next;
    struct st_picoquic_stream_message* prev;
} picoquic_stream_message_t;

/* Per-stream semi-reliable state */
typedef struct st_picoquic_semi_reliable_ctx {
    int enabled;                        /* Is this stream semi-reliable? */
    uint64_t default_lifetime_us;       /* Default message lifetime */
    picoquic_stream_message_t* messages; /* Linked list of active messages */
    picoquic_stream_message_t* tail;    /* Tail for O(1) append */
    uint64_t skip_offset;              /* Highest offset where STREAM_SKIP was sent */
    uint64_t messages_sent;             /* Total messages written */
    uint64_t messages_skipped;          /* Total messages skipped */
    uint64_t bytes_skipped;             /* Total bytes skipped */
} picoquic_semi_reliable_ctx_t;

/* ========================================================================
 * Public API
 * ======================================================================== */

/* Mark a stream as semi-reliable with a default message lifetime.
 * Must be called before writing data. lifetime_us=0 means fully reliable. */
void picoquic_stream_set_semi_reliable(
    struct st_picoquic_cnx_t* cnx,
    uint64_t stream_id,
    uint64_t default_lifetime_us);

/* Write a message with explicit lifetime and priority.
 * Records message boundary for deadline-based retransmit decisions.
 * depends_on=0 means no dependency. */
int picoquic_stream_write_message(
    struct st_picoquic_cnx_t* cnx,
    uint64_t stream_id,
    const uint8_t* data, size_t length,
    uint64_t lifetime_us,
    uint8_t priority,
    uint64_t depends_on);

/* Check if any messages on this stream have expired and should be skipped.
 * Called from the retransmit path. Returns number of messages skipped. */
int picoquic_semi_reliable_check_expiry(
    struct st_picoquic_cnx_t* cnx,
    uint64_t stream_id,
    uint64_t current_time);

/* Process a received STREAM_SKIP frame.
 * Advances the receiver's read offset past the skipped region. */
int picoquic_process_stream_skip(
    struct st_picoquic_cnx_t* cnx,
    const uint8_t* bytes, size_t bytes_max,
    size_t* consumed);

/* Format a STREAM_SKIP frame into the output buffer. */
uint8_t* picoquic_format_stream_skip(
    uint8_t* bytes, const uint8_t* bytes_max,
    uint64_t stream_id, uint64_t offset, uint64_t length);

/* Process a received STREAM_SKIP_REQUEST frame.
 * Receiver asks sender to skip data below the given offset. */
int picoquic_process_stream_skip_request(
    struct st_picoquic_cnx_t* cnx,
    const uint8_t* bytes, size_t bytes_max,
    size_t* consumed);

/* Format a STREAM_SKIP_REQUEST frame. */
uint8_t* picoquic_format_stream_skip_request(
    uint8_t* bytes, const uint8_t* bytes_max,
    uint64_t stream_id, uint64_t skip_until_offset);

/* Free all semi-reliable state for a stream (called on stream close). */
void picoquic_semi_reliable_free(
    picoquic_semi_reliable_ctx_t* ctx);

#ifdef __cplusplus
}
#endif

#endif /* SEMI_RELIABLE_H */
