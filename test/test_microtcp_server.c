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
 * You can use this file to write a test microTCP server.
 * This file is already inserted at the build system.
 */

#include "../lib/microtcp.c"
#include "netinet/in.h"
#include <stdio.h>

const int local_port = 10000;

int
main(int argc, char **argv)
{
  struct sockaddr_in sin;
  struct sockaddr client_address;
  void *buf = malloc(sizeof(int)*10000);

  microtcp_sock_t sock = microtcp_socket (AF_INET, 0, 0);

  memset (&sin, 0, sizeof(struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_port = htons (local_port);
  sin.sin_addr.s_addr = htonl(INADDR_ANY);

  
  if (microtcp_bind(&sock, (struct sockaddr *) &sin, sizeof(struct sockaddr_in)) != 0) {
    printf("Bind Error!\n");
    return -1;
  }
  if (microtcp_accept(&sock, (struct sockaddr *) &client_address, sizeof(struct sockaddr_in)) != 0) {
    printf("Connect Error!\n");
    return -1;
  }
  

  ssize_t recved;
  int i, j;
  
  printf("Recved: %d\n", microtcp_recv(&sock, buf, sizeof(int)*10000, 0));
  printf("Data: \n");
  for (i=9990; i<10000; i++) {
    printf("%d)%d\t", i, ((int*)buf)[i]);
	if (i%5==4) printf("\n");
  }
  printf("\n");

 
  while (1) {
    recved = microtcp_recv(&sock, buf, sizeof(int), 0);
    if (recved == -1) {
	  continue;
    } else if (recved <= 0) break;
    printf("Receiving: %d\n", *((int*)buf));
  }
  free(buf);
  return 0;
}
