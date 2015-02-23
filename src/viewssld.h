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

#ifndef __SSLUNCRYPT_H__
#define __SSLUNCRYPT_H__

#include <libnet.h>


#define CHAR_PER_LINE		80
#define	MAXSTRLEN		1024
#define	VALLEN			256
#define	KEYLEN			256
#define	TITLELEN		256
#define	MAX_CAP			1024
#define	DEFAULT_PID_FILE	"/var/run/viewssl.pid"
#define DEFAULT_CONFIG_FILE	"/etc/viewssld.conf"
#define	MAX_CONFIG_STR_LEN	1024
#define SOCKPATH		"/var/run/viewssl.socket"
#define	MAX_PWD_LEN		256
#define ERROR_BUF_LEN		2048
#define TCP_OPTIONS_LEN		20


struct _cap {
	char		title[TITLELEN];
	char		keyfile[FILENAME_MAX];
	char		src_interface[FILENAME_MAX];
	u_int8_t	src_interface_mac[6];
	char		dst_interface[FILENAME_MAX];
	u_int8_t	dst_interface_mac[6];
	char		pwd[MAX_PWD_LEN];
	struct	in_addr  server_ip;
	uint16_t	port;
	uint16_t	dsslport;
	int			ch[6];
};

struct	_config {
	int		loglevel;
	char	pidfilename[FILENAME_MAX];
	char	imagefile[FILENAME_MAX];
	char	config[FILENAME_MAX];
	FILE	*pidfile;
	int		daemon;
	int		index;
	struct _cap *cap[MAX_CAP];
	int		cmdl;
};

struct _errorbuf {
	char	common[ERROR_BUF_LEN];
	char	libnet[LIBNET_ERRBUF_SIZE];
};

struct _childs {
	int		index;
	pid_t	pid[MAX_CAP];
	char	*title[MAX_CAP];
};

#endif
