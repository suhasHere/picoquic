/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WINDOWS
#define WIN32_LEAN_AND_MEAN
#include "getopt.h"
#include <WinSock2.h>
#include <Windows.h>

#define SERVER_CERT_FILE "certs\\cert.pem"
#define SERVER_KEY_FILE  "certs\\key.pem"

#else /* Linux */

#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#ifndef __USE_XOPEN2K
#define __USE_XOPEN2K
#endif
#ifndef __USE_POSIX
#define __USE_POSIX
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>

#define SERVER_CERT_FILE "certs/cert.pem"
#define SERVER_KEY_FILE "certs/key.pem"
#define PICOQUIC_ECHO_ALPN "picoquic_echoed"
#define PICOQUIC_SAMPLE_SNI "test.example.com"

#endif

static const int default_server_port = 4443;
static const char* default_server_name = "::";
static const char* ticket_store_filename = "demo_ticket_store.bin";
static const char* token_store_filename = "demo_token_store.bin";


#include "picoquic.h"
#include "picoquic_packet_loop.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "datagram.h"
#include "picoquic_unified_log.h"
#include "picoquic_logger.h"
#include "picoquic_binlog.h"
/*
 * SIDUCK datagram demo call back.
 */
int echo_dg_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);

void print_address(FILE* F_log, struct sockaddr* address, char* label, picoquic_connection_id_t cnx_id)
{
    char hostname[256];

    const char* x = inet_ntop(address->sa_family,
        (address->sa_family == AF_INET) ? (void*)&(((struct sockaddr_in*)address)->sin_addr) : (void*)&(((struct sockaddr_in6*)address)->sin6_addr),
        hostname, sizeof(hostname));

    fprintf(F_log, "%016llx : ", (unsigned long long)picoquic_val64_connection_id(cnx_id));

    if (x != NULL) {
        fprintf(F_log, "%s %s, port %d\n", label, x,
            (address->sa_family == AF_INET) ? ((struct sockaddr_in*)address)->sin_port : ((struct sockaddr_in6*)address)->sin6_port);
    } else {
        fprintf(F_log, "%s: inet_ntop failed with error # %ld\n", label, WSA_LAST_ERROR(errno));
    }
}

/* server loop call back management */
typedef struct st_server_loop_cb_t {
    int just_once;
    int first_connection_seen;
    int connection_done;
} server_loop_cb_t;

static int server_loop_cb(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode, void* callback_ctx)
{
    int ret = 0;
    server_loop_cb_t* cb_ctx = (server_loop_cb_t*)callback_ctx;

    if (cb_ctx == NULL) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else {
        switch (cb_mode) {
        case picoquic_packet_loop_ready:
            fprintf(stdout, "Waiting for packets.\n");
            break;
        case picoquic_packet_loop_after_receive:
					  break;
        case picoquic_packet_loop_after_send:
            break;
        default:
            ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
            break;
        }

        if (ret == 0 && cb_ctx->just_once){
            if (!cb_ctx->first_connection_seen && picoquic_get_first_cnx(quic) != NULL) {
                cb_ctx->first_connection_seen = 1;
                fprintf(stdout, "First connection noticed.\n");
            } else if (cb_ctx->first_connection_seen && picoquic_get_first_cnx(quic) == NULL) {
                fprintf(stdout, "No more active connections.\n");
                cb_ctx->connection_done = 1;
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
            }
        }
    }
    return ret;
}

int picoquic_echo_server_callback(picoquic_cnx_t* cnx,
																	uint64_t stream_id, uint8_t* bytes, size_t length,
																	picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{

	int ret = echo_dg_callback(cnx, stream_id, bytes, length, fin_or_event, callback_ctx, v_stream_ctx);
	return ret;
}

int quic_server(const char* server_name, int server_port,
    const char* pem_cert, const char* pem_key,
    int just_once)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic_t* qserver = NULL;
    uint64_t current_time = 0;
    server_loop_cb_t loop_cb_ctx;

    memset(&loop_cb_ctx, 0, sizeof(server_loop_cb_t));
    loop_cb_ctx.just_once = just_once;

    /* Setup the server context */
    if (ret == 0) {
        current_time = picoquic_current_time();
        /* Create QUIC context */
        qserver = picoquic_create(1, pem_cert, pem_key, NULL,
																	PICOQUIC_ECHO_ALPN, picoquic_echo_server_callback,
																	NULL,
            NULL, NULL, NULL, current_time, NULL,
            NULL, NULL, 0);

        if (qserver == NULL) {
            printf("Could not create server context\n");
            ret = -1;
        }
        else {
					//picoquic_set_alpn_select_fn(qserver, picoquic_callback_select_alpn);
					picoquic_set_default_congestion_algorithm(qserver, picoquic_bbr_algorithm);
        }
    }

    if (ret == 0) {
        /* Wait for packets */
#if _WINDOWS
        ret = picoquic_packet_loop_win(qserver, server_port, 0, dest_if, server_loop_cb, &loop_cb_ctx);
#else
        ret = picoquic_packet_loop(qserver, server_port, 0, -1, server_loop_cb, &loop_cb_ctx);
#endif
    }

    /* And exit */
    printf("Server exit, ret = 0x%x\n", ret);

    /* Clean up */
    if (qserver != NULL) {
        picoquic_free(qserver);
    }

    return ret;
}


typedef struct st_client_loop_cb_t {
    picoquic_cnx_t* cnx_client;
   	int notified_ready;
	 	int established;
	  char const* saved_alpn;
		echodg_ctx_t * echo_dg_ctx;
    struct sockaddr_storage server_address;
    struct sockaddr_storage client_address;
    picoquic_connection_id_t server_cid_before_migration;
    picoquic_connection_id_t client_cid_before_migration;
} client_loop_cb_t;

int client_loop_cb(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode, void* callback_ctx)
{
    int ret = 0;
    client_loop_cb_t* cb_ctx = (client_loop_cb_t*)callback_ctx;

    if (cb_ctx == NULL) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else {
        switch (cb_mode) {
        case picoquic_packet_loop_ready:
            fprintf(stdout, "Waiting for packets.\n");
            break;
        case picoquic_packet_loop_after_receive:
            /* Post receive callback */
            /* Keeping track of the addresses and ports, as we
             * need them to verify the migration behavior */
            if (picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_client_almost_ready && cb_ctx->notified_ready == 0) {
                /* if almost ready, display results of negotiation */
                if (picoquic_tls_is_psk_handshake(cb_ctx->cnx_client)) {
                    fprintf(stdout, "The session was properly resumed!\n");
                    picoquic_log_app_message(cb_ctx->cnx_client,
                        "%s", "The session was properly resumed!");
                }

                if (cb_ctx->cnx_client->zero_rtt_data_accepted) {
                    fprintf(stdout, "Zero RTT data is accepted!\n");
                    picoquic_log_app_message(cb_ctx->cnx_client,
                        "%s", "Zero RTT data is accepted!");
                }

                if (cb_ctx->cnx_client->alpn != NULL) {
                    fprintf(stdout, "Negotiated ALPN: %s\n", cb_ctx->cnx_client->alpn);
                    picoquic_log_app_message(cb_ctx->cnx_client,
                        "Negotiated ALPN: %s", cb_ctx->cnx_client->alpn);
                    cb_ctx->saved_alpn = picoquic_string_duplicate(cb_ctx->cnx_client->alpn);
                }
                fprintf(stdout, "Almost ready!\n\n");
                cb_ctx->notified_ready = 1;
            }
            break;
        case picoquic_packet_loop_after_send:
            if (picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_disconnected) {
            	  fprintf(stdout, "disconnected\n");
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
            }
            else if (ret == 0 && cb_ctx->established == 0 && (picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_ready ||
                picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_client_ready_start)) {
                printf("Connection established. Version = %x, I-CID: %llx, verified: %d\n",
                    picoquic_supported_versions[cb_ctx->cnx_client->version_index].version,
                    (unsigned long long)picoquic_val64_connection_id(picoquic_get_logging_cnxid(cb_ctx->cnx_client)),
                    cb_ctx->cnx_client->is_hcid_verified);

                picoquic_log_app_message(cb_ctx->cnx_client,
                    "Connection established. Version = %x, I-CID: %llx, verified: %d",
                    picoquic_supported_versions[cb_ctx->cnx_client->version_index].version,
                    (unsigned long long)picoquic_val64_connection_id(picoquic_get_logging_cnxid(cb_ctx->cnx_client)),
                    cb_ctx->cnx_client->is_hcid_verified);
                cb_ctx->established = 1;
            }
            break;
        default:
            ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
            break;
        }
    }
    return ret;
}

/* Quic Client */
int quic_client(const char* ip_address_text, int server_port)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic_t* qclient = NULL;
    picoquic_cnx_t* cnx_client = NULL;
    uint64_t current_time = 0;
    int is_name = 0;
    echodg_ctx_t * echodg_ctx = NULL;
    client_loop_cb_t loop_cb;

    memset(&loop_cb, 0, sizeof(client_loop_cb_t));
    const char* sni = NULL;
		echodg_ctx = create_echodg_ctx();
		if(echodg_ctx == NULL) {
			fprintf(stdout, "unable to create datagram echo context\n");
			return -1;
		}

    if (ret == 0) {
        ret = picoquic_get_server_address(ip_address_text, server_port, &loop_cb.server_address, &is_name);
        if (sni == NULL && is_name != 0) {
            sni = ip_address_text;
        }
    }

    /* Create QUIC context */
    current_time = picoquic_current_time();

    if (ret == 0) {
        qclient = picoquic_create(1, NULL, NULL,
																	NULL, PICOQUIC_ECHO_ALPN,NULL, NULL,
																	NULL, NULL, NULL,
																	current_time, NULL, ticket_store_filename,
																	NULL, 0);

        if (qclient == NULL) {
            ret = -1;
        } else {
            picoquic_set_default_congestion_algorithm(qclient, picoquic_bbr_algorithm);
            if (picoquic_load_retry_tokens(qclient, token_store_filename) != 0) {
                fprintf(stderr, "No token file present. Will create one as <%s>.\n", token_store_filename);
            }
        }
    }

    /* Create the client connection */
    if (ret == 0) {
        /* Create a client connection */
        cnx_client = picoquic_create_cnx(qclient, picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)&loop_cb.server_address, current_time,
            0, PICOQUIC_SAMPLE_SNI, PICOQUIC_ECHO_ALPN, 1);

        if (cnx_client == NULL) {
            ret = -1;
        }
        else {
					picoquic_set_callback(cnx_client, echo_dg_callback, echodg_ctx);
					cnx_client->local_parameters.max_datagram_frame_size = 128;

            fprintf(stdout, "Max stream id bidir remote before start = %d (%d)\n",
                (int)cnx_client->max_stream_id_bidir_remote,
                (int)cnx_client->remote_parameters.initial_max_stream_id_bidir);

            if (ret == 0) {
                ret = picoquic_start_client_cnx(cnx_client);

                printf("Starting client connection. Version = %x, I-CID: %llx\n",
                    picoquic_supported_versions[cnx_client->version_index].version,
                    (unsigned long long)picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx_client)));

                fprintf(stdout, "Max stream id bidir remote after start = %d (%d)\n",
                    (int)cnx_client->max_stream_id_bidir_remote,
                    (int)cnx_client->remote_parameters.initial_max_stream_id_bidir);
            }
        }
    }

    /* Wait for packets */
    if (ret == 0) {
        loop_cb.cnx_client = cnx_client;
        loop_cb.echo_dg_ctx = echodg_ctx;

#ifdef _WINDOWS
        ret = picoquic_packet_loop_win(qclient, 0, loop_cb.server_address.ss_family, 0, client_loop_cb, &loop_cb);
#else
        ret = picoquic_packet_loop(qclient, 0, loop_cb.server_address.ss_family, 0, client_loop_cb, &loop_cb);
#endif
    }

    if (ret == 0) {
        uint64_t last_err;
        
        if ((last_err = picoquic_get_local_error(cnx_client)) != 0) {
            fprintf(stdout, "Connection end with local error 0x%" PRIx64 ".\n", last_err);
            ret = -1;
        }
        if ((last_err = picoquic_get_remote_error(cnx_client)) != 0) {
            fprintf(stdout, "Connection end with remote error 0x%" PRIx64 ".\n", last_err);
            ret = -1;
        }
        if ((last_err = picoquic_get_application_error(cnx_client)) != 0) {
            fprintf(stdout, "Connection end with application error 0x%" PRIx64 ".\n", last_err);
            ret = -1;
        }

        /* Report on successes and failures */
        if (cnx_client->nb_zero_rtt_sent != 0) {
            fprintf(stdout, "Out of %d zero RTT packets, %d were acked by the server.\n",
                cnx_client->nb_zero_rtt_sent, cnx_client->nb_zero_rtt_acked);
            picoquic_log_app_message(cnx_client, "Out of %d zero RTT packets, %d were acked by the server.",
                cnx_client->nb_zero_rtt_sent, cnx_client->nb_zero_rtt_acked);
        }

        fprintf(stdout, "Quic Bit was %sgreased by the client.\n", (cnx_client->quic_bit_greased) ? "" : "NOT ");
        fprintf(stdout, "Quic Bit was %sgreased by the server.\n", (cnx_client->quic_bit_received_0) ? "" : "NOT ");

        if (cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect0_total_local != 0 ||
            cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect1_total_local != 0 ||
            cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ce_total_local != 0) {
            fprintf(stdout, "ECN was received (ect0: %" PRIu64 ", ect1: %" PRIu64 ", ce: %" PRIu64 ").\n",
                cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect0_total_local,
                cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect1_total_local,
                cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ce_total_local);
        }
        else {
            fprintf(stdout, "ECN was not received.\n");
        }

        if (cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect0_total_remote != 0 ||
            cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect1_total_remote != 0 ||
            cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ce_total_remote != 0) {
            fprintf(stdout, "ECN was acknowledged (ect0: %" PRIu64 ", ect1: %" PRIu64 ", ce: %" PRIu64 ").\n",
                cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect0_total_remote,
                cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect1_total_remote,
                cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ce_total_remote);
        }
        else {
            fprintf(stdout, "ECN was not acknowledged.\n");
        }

        if (picoquic_get_data_received(cnx_client) > 0) {
            double duration_usec = (double)(picoquic_get_quic_time(qclient) - picoquic_get_cnx_start_time(cnx_client));

            if (duration_usec > 0) {
                double receive_rate_mbps = 8.0 * ((double)picoquic_get_data_received(cnx_client)) / duration_usec;
                fprintf(stdout, "Received %llu bytes in %f seconds, %f Mbps.\n",
                    (unsigned long long)picoquic_get_data_received(cnx_client),
                    duration_usec / 1000000.0, receive_rate_mbps);
                picoquic_log_app_message(cnx_client, "Received %llu bytes in %f seconds, %f Mbps.",
                    (unsigned long long)picoquic_get_data_received(cnx_client),
                    duration_usec / 1000000.0, receive_rate_mbps);
            }
        }
    }

    /* Clean up */
    free(echodg_ctx);

    if (loop_cb.saved_alpn != NULL) {
        free((void *)loop_cb.saved_alpn);
        loop_cb.saved_alpn = NULL;
    }

    return ret;
}

uint32_t parse_target_version(char const* v_arg)
{
    /* Expect the version to be encoded in base 16 */
    uint32_t v = 0;
    char const* x = v_arg;

    while (*x != 0) {
        int c = *x;

        if (c >= '0' && c <= '9') {
            c -= '0';
        } else if (c >= 'a' && c <= 'f') {
            c -= 'a';
            c += 10;
        } else if (c >= 'A' && c <= 'F') {
            c -= 'A';
            c += 10;
        } else {
            v = 0;
            break;
        }
        v *= 16;
        v += c;
        x++;
    }

    return v;
}

void usage()
{
    fprintf(stderr, "PicoQUIC demo client and server\n");
    fprintf(stderr, "Usage: picoquicdemo <options> [server_name [port [scenario]]] \n");
    fprintf(stderr, "  For the client mode, specify server_name and port.\n");
    fprintf(stderr, "  For the server mode, use -p to specify the port.\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -c file               cert file (default: %s)\n", SERVER_CERT_FILE);
    fprintf(stderr, "  -e if                 Send on interface (default: -1)\n");
    fprintf(stderr, "                           -1: receiving interface\n");
    fprintf(stderr, "                            0: routing lookup\n");
    fprintf(stderr, "                            n: ifindex\n");
    fprintf(stderr, "  -f migration_mode     Force client to migrate to start migration:\n");
    fprintf(stderr, "                        -f 1  test NAT rebinding,\n");
    fprintf(stderr, "                        -f 2  test CNXID renewal,\n");
    fprintf(stderr, "                        -f 3  test migration to new address.\n");
    fprintf(stderr, "  -h                    This help message\n");
    fprintf(stderr, "  -i <src mask value>   Connection ID modification: (src & ~mask) || val\n");
    fprintf(stderr, "                        Implies unconditional server cnx_id xmit\n");
    fprintf(stderr, "                          where <src> is int:\n");
    fprintf(stderr, "                            0: picoquic_cnx_id_random\n");
    fprintf(stderr, "                            1: picoquic_cnx_id_remote (client)\n");
    fprintf(stderr, "                            2: same as 0, plus encryption of unmasked data\n");
    fprintf(stderr, "                            3: same as 0, plus encryption of all data\n");
    fprintf(stderr, "                        val and mask must be hex strings of same length, 4 to 18\n");
    fprintf(stderr, "  -k file               key file (default: %s)\n", SERVER_KEY_FILE);
    fprintf(stderr, "  -K file               ESNI private key file (default: don't use ESNI)\n");
    fprintf(stderr, "  -E file               ESNI RR file (default: don't use ESNI)\n");
    fprintf(stderr, "  -C cipher_suite_id    specify cipher suite (e.g. -C 20 = chacha20)\n");
    fprintf(stderr, "  -o folder             Folder where client writes downloaded files,\n");
    fprintf(stderr, "                        defaults to current directory.\n");
    fprintf(stderr, "  -w folder             Folder containing web pages served by server\n");
    fprintf(stderr, "  -l file               Log file, Log to stdout if file = \"-\". No logging if absent.\n");
    fprintf(stderr, "  -b bin_dir            Binary logging to this directory. No binary logging if absent.\n");
    fprintf(stderr, "  -q qlog_dir           Qlog logging to this directory. No qlog logging if absent,\n");
    fprintf(stderr, "                        but qlogs could be extracted from binary logs using picolog\n");
    fprintf(stderr, "                        if binary logs are available.\n");
    fprintf(stderr, "                        Production of qlogs on servers affects performance.\n");
    fprintf(stderr, "  -L                    Log all packets. If absent, log stops after 100 packets.\n");
    fprintf(stderr, "  -p port               server port (default: %d)\n", default_server_port);
    fprintf(stderr, "  -m mtu_max            Largest mtu value that can be tried for discovery\n");
    fprintf(stderr, "  -n sni                sni (default: server name)\n");
    fprintf(stderr, "  -a alpn               alpn (default function of version)\n");
    fprintf(stderr, "  -r                    Do Reset Request\n");
    fprintf(stderr, "  -s <64b 64b>          Reset seed\n");
    fprintf(stderr, "  -t file               root trust file\n");
    fprintf(stderr, "  -u nb                 trigger key update after receiving <nb> packets on client\n");
    fprintf(stderr, "  -v version            Version proposed by client, e.g. -v ff000012\n");
    fprintf(stderr, "  -z                    Set TLS zero share behavior on client, to force HRR.\n");
    fprintf(stderr, "  -1                    Once: close the server after processing 1 connection.\n");
    fprintf(stderr, "  -S solution_dir       Set the path to the source files to find the default files\n");
    fprintf(stderr, "  -I length             Length of CNX_ID used by the client, default=8\n");
    fprintf(stderr, "  -G cc_algorithm       Use the specified congestion control algorithm:\n");
    fprintf(stderr, "                        reno, cubic or fast. Defaults to cubic.\n");
    fprintf(stderr, "  -D                    no disk: do not save received files on disk.\n");
    fprintf(stderr, "  -Q                    send a large client hello in order to test post quantum\n");
    fprintf(stderr, "                        readiness.\n");
    fprintf(stderr, "  -R                    randomize initial packet number\n");

    fprintf(stderr, "\nThe scenario argument specifies the set of files that should be retrieved,\n");
    fprintf(stderr, "and their order. The syntax is:\n");
    fprintf(stderr, "  *{[<stream_id>':'[<previous_stream>':'[<format>:]]]path;}\n");
    fprintf(stderr, "where:\n");
    fprintf(stderr, "  <stream_id>:          The numeric ID of the QUIC stream, e.g. 4. By default, the\n");
    fprintf(stderr, "                        next stream in the logical QUIC order, 0, 4, 8, etc.");
    fprintf(stderr, "  <previous_stream>:    The numeric ID of the previous stream. The GET command will\n");
    fprintf(stderr, "                        be issued after that stream's transfer finishes. By default,\n");
    fprintf(stderr, "                        previous stream in this scenario.\n");
    fprintf(stderr, "  <format>:             Whether the received file should be written to disc as\n");
    fprintf(stderr, "                        binary(b) or text(t). Defaults to text.\n");
    fprintf(stderr, "  <path>:               The name of the document that should be retrieved\n");
    fprintf(stderr, "If no scenario is specified, the client executes the default scenario.\n");

    exit(1);
}

int main(int argc, char** argv)
{
    const char * server_name = default_server_name;
    int server_port = default_server_port;
    int is_client = 0;
    int just_once = 0;
    int ret = 0;

#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif

    /* Get the parameters */
    int opt;
    while ((opt = getopt(argc, argv, "c:k:K:p:u:v:o:w:f:i:s:e:E:C:l:b:q:m:n:a:t:S:I:G:1rRhzDLQ")) != -1) {
        switch (opt) {
        case 'p':
            if ((server_port = atoi(optarg)) <= 0) {
                fprintf(stderr, "Invalid port: %s\n", optarg);
                usage();
            }
            break;
        case '1':
            just_once = 1;
            break;
        case 'h':
            usage();
            break;
        default:
            usage();
            break;
        }
    }

    /* Simplified style params */
    if (optind < argc) {
        server_name = argv[optind++];
        is_client = 1;
    }

    if (optind < argc) {
        if ((server_port = atoi(argv[optind++])) <= 0) {
            fprintf(stderr, "Invalid port: %s\n", optarg);
            usage();
        }
    }

    if (optind < argc) {
        usage();
    }

    if (is_client == 0) {

        /* Run as server */
        printf("Starting Picoquic server (v%s) on port %d, server name = %s, just_once = %d\n",
            PICOQUIC_VERSION, server_port, server_name, just_once);
        ret = quic_server(server_name, server_port,
            SERVER_CERT_FILE, SERVER_KEY_FILE, just_once);
        printf("Server exit with code = %d\n", ret);
    } else {
        /* Run as client */
        printf("Starting Picoquic (v%s) connection to server = %s, port = %d\n", PICOQUIC_VERSION, server_name, server_port);
        ret = quic_client(server_name, server_port);

        printf("Client exit with code = %d\n", ret);
    }
    
}
