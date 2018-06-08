/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2015-2017  Manolis Surligas <surligas@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* 1 = ACK || 2 = RST || 4 = SYN || 8 = FIN ----- << 12 */

#include "microtcp.h"
#include "../utils/crc32.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#define TIMEOUT_ERROR -1
#define CRC_ERROR -2
#define CONTROL_ERROR -3
#define ACKNO_ERROR -4
#define STATE_ERROR -5
#define SHUTDOWN_CODE -10


#define min(a, b) (((a) < (b)) ? (a) : (b))

#include <unistd.h>

ssize_t
send_segment (microtcp_sock_t *socket, const void *buffer, size_t length,
               int flags);
ssize_t
recv_segment (microtcp_sock_t *socket, void *buffer, size_t length, int flags);

microtcp_sock_t
microtcp_socket (int domain, int type, int protocol)
{
  microtcp_sock_t sock;

  if ((sock.sd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
  	sock.state = INVALID;
  	perror("Socket failure");
  	return sock;
  }
  sock.packets_send = 0;
  sock.packets_received = 0;
  sock.packets_lost = 0;
  sock.bytes_send = 0;
  sock.bytes_received = 0;
  sock.bytes_lost = 0;
  sock.state = UNKNOWN;
  sock.address = malloc(sizeof(struct sockaddr)); /* DONT FORGET TO FREE */
  sock.recvbuf = malloc(MICROTCP_RECVBUF_LEN);
  sock.buf_fill_level = 0;
  sock.cwnd = MICROTCP_INIT_CWND;
  sock.ssthresh = MICROTCP_INIT_SSTHRESH;
  sock.cong_alg = SLOW_START;
  
  time_t t;
  srand((unsigned) time(&t));

  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = MICROTCP_ACK_TIMEOUT_US;
  if (setsockopt(sock.sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0) {
    perror("setsockopt");
  }

  return sock;
}

int
microtcp_bind (microtcp_sock_t *socket, const struct sockaddr *address,
               socklen_t address_len)
{
  if (socket->state != UNKNOWN) return STATE_ERROR;

  if (bind(socket->sd, address, address_len) == -1) {
    socket->state = INVALID;
    perror("bind");
    return -1;
  }
  socket->state = BIND;
  return 0;
}

int
microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len)
{
  if (socket->state != BIND) return STATE_ERROR;

  microtcp_header_t hsend, hrecv;
  ssize_t sent, recved;

/* UPDATE SOCKET */
  socket->seq_number = 0/*rand()*/;

/* HOST SYN */
  /* prepare header */
  memset(&hsend, 0, sizeof(microtcp_header_t));
  hsend.control = htons(4 << 12);
  hsend.seq_number = htonl(socket->seq_number);
  hsend.window = htons(MICROTCP_WIN_SIZE);
  /* send */
  sent = sendto(socket->sd, (const void *)&hsend, sizeof(microtcp_header_t), 0, address, address_len);
  socket->packets_send++;
  socket->bytes_send += sent;

/* PEER ACK SYN*/
  /* receive */
  recved = recvfrom(socket->sd, (void *)&hrecv, sizeof(microtcp_header_t), 0, (struct sockaddr *)address, &address_len);
  if (recved < 0) return TIMEOUT_ERROR;
  socket->packets_received++;
  socket->bytes_received += recved;
  /* analyze */
  if (ntohs(hrecv.control) != (5 << 12)) {
    perror("Connect error. Peer ACK SYN fail. ");
    return CONTROL_ERROR;
  }
  if (ntohl(hrecv.ack_number) != socket->seq_number + sizeof(microtcp_header_t)) {
    return ACKNO_ERROR;
  }

/* UPDATE SOCKET */
  socket->seq_number = ntohl(hrecv.ack_number);
  socket->ack_number = ntohl(hrecv.seq_number) + recved;
  socket->init_win_size = ntohs(hrecv.window);

/* HOST ACK */
  /* prepare header */
  memset(&hsend, 0, sizeof(microtcp_header_t));
  hsend.control = htons(1 << 12);
  hsend.seq_number = htonl(socket->seq_number);
  hsend.ack_number = htonl(socket->ack_number);
  /* send */
  sent = sendto(socket->sd, &hsend, sizeof(microtcp_header_t), 0, address, address_len);
  socket->packets_send++;
  socket->bytes_send += sent;

/* FINISH */
  socket->state = ESTABLISHED;
  memcpy(socket->address, address, sizeof(struct sockaddr));
  memcpy(&(socket->address_len), &address_len, sizeof(socklen_t));
  return 0;
}

int
microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address,
                 socklen_t address_len)
{
  if (socket->state != BIND) return STATE_ERROR;

  microtcp_header_t hrecv, hsend;
  ssize_t recved, sent;
  address_len = sizeof(struct sockaddr);

/* PEER SYN */
  /* receive */
  do {
    recved = recvfrom(socket->sd, (void *)&hrecv, sizeof(microtcp_header_t), 0, address, &address_len);
  } while (recved < 0);
  socket->packets_received++;
  socket->bytes_received += recved;
  /* analyze */
  if (ntohs(hrecv.control) != (4 << 12)) {
    perror("Accept error. Peer SYN fail. ");
    return CONTROL_ERROR;
  }
/* UPDATE SOCKET */
  socket->seq_number = 0/*rand()*/;
  socket->ack_number = ntohl(hrecv.seq_number) + recved;
  socket->init_win_size = ntohs(hrecv.window);

/* HOST ACK SYN */
  /* prepare header */
  memset(&hsend, 0, sizeof(microtcp_header_t));
  hsend.control = htons(5 << 12);
  hsend.ack_number = htonl(socket->ack_number);
  hsend.seq_number = htonl(socket->seq_number);
  hsend.window = htons(MICROTCP_WIN_SIZE);
  /* send */
  sent = sendto(socket->sd, &hsend, sizeof(microtcp_header_t), 0, address, address_len);
  socket->packets_send++;
  socket->bytes_send += sent;

/* PEER ACK */
  /* receive */
  recved = recvfrom(socket->sd, (void *)&hrecv, sizeof(microtcp_header_t), 0, address, &address_len);
  if (recved < 0) return TIMEOUT_ERROR;
  socket->packets_received++;
  socket->bytes_received += recved;
  /* analyze */
  if (ntohs(hrecv.control) != (1 << 12)) {
    perror("Accept error. Peer ACK fail. ");
    return CONTROL_ERROR;
  }
  if (ntohl(hrecv.ack_number) != socket->seq_number + sizeof(microtcp_header_t)){
    return ACKNO_ERROR;
  }

/* UPDATE SOCKET */
  socket->seq_number = ntohl(hrecv.ack_number);

/* FINISH */
  socket->state = ESTABLISHED;
  memcpy(socket->address, address, sizeof(struct sockaddr));
  memcpy(&(socket->address_len), &address_len, sizeof(socklen_t));
  return 0;
}

int
microtcp_shutdown (microtcp_sock_t *socket, int how)
{
  if (socket->state != ESTABLISHED && socket->state != CLOSING_BY_PEER) return STATE_ERROR;

  microtcp_header_t hsend, hrecv;
  ssize_t sent, recved;

  if (socket->state != CLOSING_BY_PEER) socket->state = CLOSING_BY_HOST;
/* HOST FIN */
  /* prepare header */
  memset(&hsend, 0, sizeof(microtcp_header_t));
  hsend.control = htons(8 << 12);
  hsend.seq_number = htonl(socket->seq_number);
  /* send */
  sent = sendto(socket->sd, &hsend, sizeof(microtcp_header_t), 0, socket->address, socket->address_len);
  socket->packets_send++;
  socket->bytes_send += sent;

/* PEER ACK */
  /* receive */
  recved = recvfrom(socket->sd, (void *)&hrecv, sizeof(microtcp_header_t), 0, socket->address, &(socket->address_len));
  socket->packets_received++;
  socket->bytes_received += recved;
  /* analyze */
  if (ntohs(hrecv.control) != (1 << 12)) {
    perror("Shutdown error. Peer ACK fail. ");
    return CONTROL_ERROR;
  }

  if (socket->state == CLOSING_BY_HOST) {
/* PEER FIN */
    /* receive */
    recved = recvfrom(socket->sd, (void *)&hrecv, sizeof(microtcp_header_t), 0, socket->address, &(socket->address_len));
    socket->packets_received++;
    socket->bytes_received += recved;
    /* analyze */
    if (ntohs(hrecv.control) != (8 << 12)) {
      perror("Shutdown error. Peer FIN fail. ");
      return CONTROL_ERROR;
    }

/* HOST ACK */
    /* prepare header */
    memset(&hsend, 0, sizeof(microtcp_header_t));
    hsend.control = htons(1 << 12);
    hsend.seq_number = htonl(socket->seq_number);
    hsend.ack_number = htonl(socket->ack_number);
    /* send */
    sent = sendto(socket->sd, &hsend, sizeof(microtcp_header_t), 0, socket->address, socket->address_len);
    socket->packets_send++;
    socket->bytes_send += sent;
  }

/* FINISH */
  socket->state = CLOSED;
  /* print statistics */
  printf("CONNECTION TERMINATED GRACEFULLY :)\n");
  printf("Packets sent: %d\n", socket->packets_send);
  printf("Packets received: %d\n", socket->packets_received);
  printf("Packets lost: %d\n", socket->packets_lost);
  printf("Bytes sent: %d\n", socket->bytes_send);
  printf("Bytes received: %d\n", socket->bytes_received);
  printf("Bytes lost: %d\n", socket->bytes_lost, (100*socket->bytes_lost)/(socket->bytes_received+socket->bytes_lost));

  return 0;
}

ssize_t
microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length,
               int flags)
{
  if (socket->state != ESTABLISHED) return STATE_ERROR;

  size_t remaining = length, bytes_to_send;
  ssize_t sent;
  void *buffer_index =(void *) buffer;
  
  socket->curr_win_size = socket->init_win_size;
  while (remaining != 0) {
    bytes_to_send = min(remaining, min(socket->curr_win_size, socket->cwnd));
printf("rem: %d, win: %d, cwin: %d\n", remaining, socket->curr_win_size, socket->cwnd);
printf("bts: %d\n", bytes_to_send);
	sent = send_segment(socket, buffer_index, bytes_to_send, flags);
	if (sent == 0) continue;
	buffer_index += sent;
	remaining -= sent;
	/* congestion */
    if (socket->cong_alg == CONGESTION_AVOIDANCE) socket->cwnd += MICROTCP_MSS;
    if (socket->cwnd > socket->ssthresh) socket->cong_alg = CONGESTION_AVOIDANCE;
  }
  
  return length;
}

ssize_t
send_segment (microtcp_sock_t *socket, const void *buffer, size_t length,
               int flags)
{
  microtcp_header_t *hrecv;
  ssize_t sent = 0, recved;
  void *buf = malloc(sizeof(microtcp_header_t) + MICROTCP_MSS);
  size_t total_sent = 0, i, j = 0, chunks = length / MICROTCP_MSS;

  for(i = 0; i < chunks; i++) {
	memset(buf, 0, sizeof(microtcp_header_t) + MICROTCP_MSS);
    /* finish DATA header */
    ((microtcp_header_t *)buf)->seq_number = htonl(socket->seq_number + i*(MICROTCP_MSS + sizeof(microtcp_header_t)));
    /* copy chuck */
    memcpy(buf + sizeof(microtcp_header_t), buffer + i*MICROTCP_MSS, MICROTCP_MSS);
	/* crc32 */
printf("crc %lu\n", crc32(buf, sizeof(microtcp_header_t) + MICROTCP_MSS));
    ((microtcp_header_t *)buf)->checksum = htonl(crc32(buf, sizeof(microtcp_header_t) + MICROTCP_MSS));
	/* send */
printf("sending chunk %d of %d with seq# %d\n", i+1, chunks, socket->seq_number + i*(MICROTCP_MSS + sizeof(microtcp_header_t)));
	sent = sendto(socket->sd, buf, sizeof(microtcp_header_t) + MICROTCP_MSS, flags, socket->address, socket->address_len);
	socket->packets_send++;
	socket->bytes_send += sent;
  }
  if(length % MICROTCP_MSS) {
	memset(buf, 0, sizeof(microtcp_header_t) + MICROTCP_MSS%length);
	chunks++;
    /* finish DATA header */
    ((microtcp_header_t *)buf)->seq_number = htonl(socket->seq_number + (chunks-1)*(MICROTCP_MSS + sizeof(microtcp_header_t)));
    /* copy chuck */
    memcpy(buf + sizeof(microtcp_header_t), buffer + (chunks-1)*MICROTCP_MSS, length % MICROTCP_MSS);
    /* crc32 */
printf("crc %lu\n", crc32(buf, sizeof(microtcp_header_t) + length % MICROTCP_MSS));
    ((microtcp_header_t *)buf)->checksum = htonl(crc32(buf, sizeof(microtcp_header_t) + length % MICROTCP_MSS));
    /* send */
    sent = sendto(socket->sd, buf, sizeof(microtcp_header_t) + length % MICROTCP_MSS, flags, socket->address, socket->address_len);
printf("sending remaining with seq# %d\n", socket->seq_number + (chunks-1)*(MICROTCP_MSS + sizeof(microtcp_header_t)));
	socket->packets_send++;
	socket->bytes_send += sent;
  }
  /* flow control */
  if (socket->curr_win_size == 0) {
	((microtcp_header_t *)buf)->seq_number = htonl(socket->seq_number);
	sendto(socket->sd, buf, sizeof(microtcp_header_t), flags, socket->address, socket->address_len);
printf("sending without payload seq #%d\n", socket->seq_number);
	chunks++;
	usleep(rand()%MICROTCP_ACK_TIMEOUT_US);
  }
  /* ACKS */
  for(i = 0; i < chunks; i++){
printf("expecting ack#>%d\n", socket->seq_number);
    recved = recvfrom(socket->sd, buf, sizeof(microtcp_header_t), 0, socket->address, &(socket->address_len));
    if (recved < 0) {
	  /* ACK timeout */
	  socket->ssthresh /= 2;
	  socket->cwnd = min(MICROTCP_MSS, socket->ssthresh);
	  socket->cong_alg = SLOW_START;
	  break;
	}
    socket->packets_received++;
    socket->bytes_received += recved;
    /* is ACK */
    hrecv = buf;
    if (ntohs(hrecv->control) != (1 << 12)) break;
printf("got: #%d\n", htonl(hrecv->ack_number));
/* FIX ACK WRAP AROUND */
    if (htonl(hrecv->ack_number) > socket->seq_number) {
	  total_sent += abs(htonl(hrecv->ack_number) - socket->seq_number) - sizeof(microtcp_header_t);
      socket->seq_number = ntohl(hrecv->ack_number);
	  socket->curr_win_size = ntohs(hrecv->window);
	  if (socket->cong_alg == SLOW_START) socket->cwnd += MICROTCP_MSS;
	} else {
	  socket->ssthresh = socket->cwnd/2;
	  socket->cwnd = socket->cwnd/2 + 1;
    }
  }
printf("\n");
  free(buf);
  return total_sent;
}

ssize_t
microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  if (socket->state != ESTABLISHED) return STATE_ERROR;

  size_t remaining = length;
  ssize_t recv;
  void *buffer_index = buffer;
  
  while (remaining != 0) {
	recv = recv_segment (socket, socket->recvbuf + socket->buf_fill_level,(int) NULL, flags);
	/* flush socket buffer */
	if (100*socket->buf_fill_level >= 70*MICROTCP_RECVBUF_LEN) {
	  memcpy(buffer_index, socket->recvbuf, socket->buf_fill_level);
	  buffer_index += socket->buf_fill_level;
	  socket->buf_fill_level = 0;
	}
	if (recv == SHUTDOWN_CODE) {
	  /* shutdown */
      break;
	} else if (recv < 0) continue;
	remaining -= recv;
  }
  memcpy(buffer_index, socket->recvbuf, socket->buf_fill_level);
  buffer_index += socket->buf_fill_level;
  socket->buf_fill_level = 0;

  return length;
}

ssize_t
recv_segment (microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  microtcp_header_t hsend, *hrecv;
  ssize_t recved, sent;
  void *buf = malloc(sizeof(microtcp_header_t) + MICROTCP_MSS);
  uint32_t checksum;

  /* prepare ACK header */
  memset(&hsend, 0, sizeof(microtcp_header_t));
  hsend.control = htons(1 << 12);
  
  recved = recvfrom(socket->sd, buf, sizeof(microtcp_header_t) + MICROTCP_MSS, flags, socket->address, &(socket->address_len));
  if (recved < 0) {
    free(buf);
	return TIMEOUT_ERROR;
  }
  socket->packets_received++;
  socket->bytes_received += recved;
  hrecv = buf;
  /* crc32 */
  checksum = ntohl(hrecv->checksum);
  hrecv->checksum = 0;
  if (checksum != 0 && checksum != crc32(buf, recved)) {
    socket->packets_lost++;
    socket->bytes_lost += recved;
	hsend.ack_number = htonl(socket->ack_number);
    sent = sendto(socket->sd, &hsend, sizeof(microtcp_header_t), flags, socket->address, socket->address_len);
    socket->packets_send++;
	socket->bytes_send += sent;
	return CRC_ERROR;
  }
  /* send ACK */
  if (ntohl(hrecv->seq_number) == socket->ack_number) socket->ack_number += recved;
  recved -= sizeof(microtcp_header_t);
  hsend.ack_number = htonl(socket->ack_number);
  socket->buf_fill_level += recved;
  hsend.window = htons(MICROTCP_WIN_SIZE - socket->buf_fill_level);
  sent = sendto(socket->sd, &hsend, sizeof(microtcp_header_t), flags, socket->address, socket->address_len);
printf("sent ack\n\n");
  socket->packets_send++;
  socket->bytes_send += sent;
  /* check if FIN */
  if (ntohs(hrecv->control) == (8 << 12)) {
    socket->state = CLOSING_BY_PEER;
    free(buf);
    microtcp_shutdown(socket, 0);
	return SHUTDOWN_CODE;
  }
  /* finalize */
  memcpy(buffer, buf + sizeof(microtcp_header_t), recved);
  free(buf);
  return recved;
}
