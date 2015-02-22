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
