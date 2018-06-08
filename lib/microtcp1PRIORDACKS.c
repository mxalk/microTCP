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

#define STATE_ERROR -4
#define CONTROL_ERROR -3
#define ACKNO_ERROR -2
#define CHECKSUM_ERROR -1

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

  time_t t;
  srand((unsigned) time(&t));

  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = MICROTCP_ACK_TIMEOUT_US;
  if (setsockopt(sock.sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0) perror("setsockopt");
 
  return sock;
}

int
microtcp_bind (microtcp_sock_t *socket, const struct sockaddr *address,
               socklen_t address_len)
{
  if (socket->state != UNKNOWN) return STATE_ERROR;

  if (bind(socket->sd, address, address_len) == -1) {
    socket->state = INVALID;
    perror("Binding failure");
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
  socket->seq_number = rand();

/* HOST SYN */
  /* prepare header */
  memset(&hsend, 0, sizeof(microtcp_header_t));
  hsend.control = htons(4 << 12);
  hsend.seq_number = htonl(socket->seq_number);
  /* send */
  sent = sendto(socket->sd, (const void *)&hsend, sizeof(microtcp_header_t), 0, address, address_len);
  socket->packets_send++;
  socket->bytes_send += sent;

/* PEER ACK SYN*/
  /* receive */
  recved = recvfrom(socket->sd, (void *)&hrecv, sizeof(microtcp_header_t), 0, (struct sockaddr *)address, &address_len);
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
  recved = recvfrom(socket->sd, (void *)&hrecv, sizeof(microtcp_header_t), 0, address, &address_len);
  socket->packets_received++;
  socket->bytes_received += recved;
  /* analyze */
  if (ntohs(hrecv.control) != (4 << 12)) {
    perror("Accept error. Peer SYN fail. ");
    return CONTROL_ERROR;
  }
/* UPDATE SOCKET */
  socket->seq_number = rand();
  socket->ack_number = ntohl(hrecv.seq_number) + recved;

/* HOST ACK SYN */
  /* prepare header */
  memset(&hsend, 0, sizeof(microtcp_header_t));
  hsend.control = htons(5 << 12);
  hsend.ack_number = htonl(socket->ack_number);
  hsend.seq_number = htonl(socket->seq_number);
  /* send */
  sent = sendto(socket->sd, &hsend, sizeof(microtcp_header_t), 0, address, address_len);
  socket->packets_send++;
  socket->bytes_send += sent;

/* PEER ACK */
  /* receive */
  recved = recvfrom(socket->sd, (void *)&hrecv, sizeof(microtcp_header_t), 0, address, &address_len);
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
  printf("Bytes lost: %d\n", socket->bytes_lost);

  return 0;
}

ssize_t
microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length,
               int flags)
{
  if (socket->state != ESTABLISHED) return STATE_ERROR;

  microtcp_header_t *hrecv;
  ssize_t sent, recved;
  void *buf = malloc(sizeof(microtcp_header_t) + length);

/* HOST SEND */
  /* prepare header */
  memset(buf, 0, sizeof(microtcp_header_t));
  ((microtcp_header_t *)buf)->seq_number = htonl(socket->seq_number);
  /* copy data */
  memcpy(buf + sizeof(microtcp_header_t), buffer, length);
  /* crc32 */
  ((microtcp_header_t *)buf)->checksum = htonl(crc32(buf, sizeof(microtcp_header_t) + length));
  /* send */
  sent = sendto(socket->sd, buf, sizeof(microtcp_header_t) + length, flags, socket->address, socket->address_len);
  socket->packets_send++;
  socket->bytes_send += sent;

/* PEER ACK */
  /* receive */
  recved = recvfrom(socket->sd, buf, sizeof(microtcp_header_t), 0, socket->address, &(socket->address_len));
  socket->packets_received++;
  socket->bytes_received += recved;

/* ANALYZE */
  hrecv = buf;
  if (ntohs(hrecv->control) != (1 << 12)) {
    perror("Send error. Peer ACK fail. ");
    free(buf);
    return CONTROL_ERROR;
  }
  if (htonl(hrecv->ack_number) != socket->seq_number + sent) {
    free(buf);
    return ACKNO_ERROR;
  }

/* UPDATE SOCKET */
  socket->seq_number = ntohl(hrecv->ack_number);

/* FINISH */
  free(buf);
  return sent;
}

ssize_t
microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  if (socket->state != ESTABLISHED) return STATE_ERROR;

  microtcp_header_t hsend, *hrecv;
  ssize_t recved, sent;
  void *buf = malloc(sizeof(microtcp_header_t) + length);
  uint32_t checksum;

/* PEER SEND */
  /* receive */
  recved = recvfrom(socket->sd, buf, sizeof(microtcp_header_t) + length, flags, socket->address, &(socket->address_len));
  socket->packets_received++;
  socket->bytes_received += recved;
  hrecv = buf;
  /* crc32 */
  checksum = ntohl(hrecv->checksum);
  hrecv->checksum = 0;
  if (checksum != 0 && checksum != crc32(buf, sizeof(microtcp_header_t) + length)) return CHECKSUM_ERROR;

/* HOST ACK */
  /* prepare header */
  memset(&hsend, 0, sizeof(microtcp_header_t));
  hsend.control = htons(1 << 12);
  hsend.ack_number = htonl(socket->ack_number + recved);
  /* send */
  sent = sendto(socket->sd, &hsend, sizeof(microtcp_header_t), flags, socket->address, socket->address_len);
  socket->packets_send++;
  socket->bytes_send += sent;

/* ANALYZE */
  if (ntohs(hrecv->control) == (8 << 12)) {
    socket->state = CLOSING_BY_PEER;
    free(buf);
    return microtcp_shutdown(socket, 0);
  }

  /* copy data */
  memcpy(buffer, buf + sizeof(microtcp_header_t), length);

/* FINISH */
  free(buf);
  return recved;
}
