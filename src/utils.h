/*
 * This file is a part of viewssld package.
 *
 * Copyright 2007 Dzmitry Plashchynski <plashchynski@gmail.com>
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
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
