/*
** This file is a part of viewssld package.
**
** Copyright (C) 2007-2008, Dzmitry Plashchynski <plashchynski@gmail.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/

#ifndef __UTILS_H__
#define __UTILS_H__

#include "viewssld.h"

//const char *SessionToString(const TcpSession *sess);
void DumpData(const u_char *data, uint32_t pkt_size);
int getmac(const char *name, u_int8_t *mac);
int load_config(const char *path, struct _config *config);
void print_config(struct _config *config);
int check_config(struct _config *config);
void usage(void);
char *gettime(void);
char *dssl_error(int n);
int optparse(struct _config *config, char argc, char *argv[], char *envp[]);
void versioninfo(void);
void errorlog(char *message);

#endif
