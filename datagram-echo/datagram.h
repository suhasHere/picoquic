#ifndef PICOQUIC_DATAGRAM_H
#define PICOQUIC_DATAGRAM_H

typedef struct st_echodg_ctx_t {
	int is_auto_alloc;
	int nb_dg_client_sent;
	int nb_dg_client_received; // echoed
	int nb_dg_server_received;
	int nb_dg_server_sent; // sent as echo
	int nb_bad_dgs;
	int nb_other_errors;
	int shutdown;
} echodg_ctx_t;


echodg_ctx_t* create_echodg_ctx();

int echo_dg_callback(picoquic_cnx_t* cnx,
										 uint64_t stream_id, uint8_t* bytes, size_t length,
										 picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);


#endif //PICOQUIC_DATAGRAM_H
