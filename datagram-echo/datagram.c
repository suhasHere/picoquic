
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include "picoquic_internal.h"
#include "datagram.h"

#define ECHO_DATAGRAM_ERROR 0x101

static const uint8_t forty_bytes[] = {0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9};

int sender_created = 0;
int shutdown_sender = 0;

int send_datagram(picoquic_cnx_t* cnx) {
	return picoquic_queue_datagram_frame(cnx, sizeof(forty_bytes), forty_bytes);
}

void* datagram_sender(void* cnx) {

	while(!shutdown_sender) {
		send_datagram((picoquic_cnx_t*) cnx);
		fprintf(stdout, "sent forty-bytes\n");
		usleep(20 * 1000);
	}
  fprintf(stdout, "sender thread exiting !!");
	pthread_exit(0);

	return NULL;
}

echodg_ctx_t * create_echodg_ctx()
{
	echodg_ctx_t* ctx = (echodg_ctx_t*)malloc(sizeof(echodg_ctx_t));

	if (ctx != NULL) {
		memset(ctx, 0, sizeof(echodg_ctx_t));
		ctx->shutdown = 0;
	}

	return ctx;
}


int check_datagram(uint8_t* bytes, size_t length) {
	int ret = 0;

	if (length != sizeof(forty_bytes) || memcmp(bytes, forty_bytes, sizeof(forty_bytes)) != 0) {
		ret = ECHO_DATAGRAM_ERROR;
	}

	return ret;
}


int echo_dg_callback(picoquic_cnx_t* cnx,
										uint64_t stream_id, uint8_t* bytes, size_t length,
										picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
	int ret = 0;
	pthread_t id; // sender thread
	echodg_ctx_t * ctx = (echodg_ctx_t*)callback_ctx;
  if (ctx == NULL) {
		ctx = create_echodg_ctx();
		if (ctx != NULL) {
			ctx->is_auto_alloc = 1;
		}
		picoquic_set_callback(cnx, echo_dg_callback, ctx);
	}
	else {
		ret = 0;
	}

	if (ret == 0) {
		switch (fin_or_event) {
			case picoquic_callback_stream_data:
			case picoquic_callback_stream_fin:
			case picoquic_callback_stream_reset: /* Client reset stream #x */
			case picoquic_callback_stop_sending: /* Client asks server to reset stream #x */
			case picoquic_callback_stream_gap:
			case picoquic_callback_prepare_to_send:
				fprintf(stdout, "Unexpected callback, code %d, length = %zu", fin_or_event, length);
				if (ctx != NULL) {
					if (ctx->is_auto_alloc) {
						free(ctx);
						ctx = NULL;
					}
					else {
						ctx->nb_other_errors++;
					}
				}
				picoquic_set_callback(cnx, NULL, NULL);
				ret = picoquic_close(cnx, ECHO_DATAGRAM_ERROR);
				break;
			case picoquic_callback_stateless_reset:
			case picoquic_callback_close: /* Received connection close */
			case picoquic_callback_application_close: /* Received application close */
				if (ctx != NULL && ctx->is_auto_alloc) {
					free(ctx);
					ctx = NULL;
				}
				// add lock
				shutdown_sender = 1;
				picoquic_set_callback(cnx, NULL, NULL);
				break;
			case picoquic_callback_version_negotiation:
				break;
			case picoquic_callback_almost_ready:
				break;
			case picoquic_callback_ready:
				/* Check that the transport parameters are what Siduck expects */
				if (cnx->remote_parameters.max_datagram_frame_size < sizeof(forty_bytes)) {
					if (ctx != NULL) {
						ctx->nb_other_errors++;
					}
					picoquic_set_callback(cnx, NULL, NULL);
					ret = picoquic_close(cnx, ECHO_DATAGRAM_ERROR);
				}
				else {
					if (cnx->client_mode) {
						if (sender_created == 0) {
							// Note: this is a hacky way to showcase sender
							// create sender thread
							pthread_create(&id, NULL, datagram_sender, cnx);
							sender_created = 1;
							fprintf(stdout, "sender thread created\n");
						}
						ret = send_datagram(cnx);
					}
				}
				break;
			case picoquic_callback_datagram:
				/* Process the datagram, which contains an address and a QUIC packet */
				if (cnx->client_mode) {
					if ((ret = check_datagram(bytes, length)) == 0) {
						if (ctx != NULL) {
							fprintf(stdout, "Received: echoed datagram\n");
						}

						if(ctx != NULL && ctx->shutdown == 1) {
							picoquic_set_callback(cnx, NULL, NULL);
							if (ctx->is_auto_alloc) {
								free(ctx);
								ctx = NULL;
							}
							ret = picoquic_close(cnx, 0);
							break;
						}

						if (ctx != NULL) {
								ctx->nb_dg_client_received++;
							}
					}
					else {
						// bad datagram
						if (ctx != NULL) {
							fprintf(stderr, "Received: datagram, but not forty-bytes\n");
						}
						else {
							fprintf(stderr, "Received a datagram, but not forty-bytes, length = %zu", length);
						}

						if (ctx != NULL) {
							ctx->nb_bad_dgs++;
						}
					}
				} else {
					// server
					if ((ret = check_datagram(bytes, length)) == 0) {
						if (ctx != NULL) {
							ctx->nb_dg_server_received++;
							// echo the data
							send_datagram(cnx);
							ctx->nb_dg_server_sent++;
						}
					}
					else {
						fprintf(stderr, "Received a datagram, but not forty-bytes, length = %zu", length);
						if (ctx != NULL) {
							ctx->nb_bad_dgs++;
						}
					}
					if(ctx != NULL && ctx->shutdown) {
						picoquic_set_callback(cnx, NULL, NULL);
						ret = picoquic_close(cnx, 0);
					}
					ret = 0;
				}
				break;
			default:
				/* unexpected */
				break;
		}
	}

	return ret;
}