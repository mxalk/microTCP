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

/*
 * You can use this file to write a test microTCP client.
 * This file is already inserted at the build system.
 */

#include "../lib/microtcp.c"
#include <stdio.h>

const char *server_address = "147.52.19.28";
const int server_port = 10000;
const int local_port = 10001;

int
main(int argc, char **argv)
{
  struct sockaddr_in sin;
  struct sockaddr_in server_sin;

  microtcp_sock_t sock = microtcp_socket (AF_INET, SOCK_DGRAM, 0);

  memset (&sin, 0, sizeof(struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_port = htons (local_port);
  sin.sin_addr.s_addr = htonl(INADDR_ANY);

  if (microtcp_bind (&sock, (struct sockaddr *) &sin, sizeof(struct sockaddr_in)) != 0) {
    printf("Bind Error!\n");
    return -1;
  }

  memset (&server_sin, 0, sizeof(struct sockaddr_in));
  server_sin.sin_family = AF_INET;
  server_sin.sin_port = htons (server_port);
  server_sin.sin_addr.s_addr = inet_addr(server_address);

  if (microtcp_connect (&sock, (struct sockaddr *) &server_sin, sizeof(struct sockaddr_in)) != 0) {
    printf("Connect Error!\n");
    return -1;
  }

  int i, j, A[10000];

  printf("Data to send: \n"); 
  for (i=0; i<10000; i++) A[i] = rand();
  for (i=9990; i<10000; i++) printf("%d ", A[i]);
  printf("\n");
  printf("Sent: %d\n", microtcp_send(&sock, A, sizeof(int)*10000, 0));
  

  for (i=0; i<0; i++) {
    j = rand();
    printf("Sending: %d\n", j);
    microtcp_send(&sock, &j, sizeof(int), 0);
  }

  microtcp_shutdown(&sock, 0);
}
