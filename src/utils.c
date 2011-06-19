/*
** This file is a part of viewssld package.
**
** Copyright (C) 2007-2008, Dmitry Plashchynski <plashchynski@gmail.com>
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

#include <string.h>
#include <openssl/ssl.h>
#include <pcap.h>
#include <ctype.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <dssl/sslcap.h>
#include <string.h>
#include <sys/ioctl.h>
#include <syslog.h>

#include "viewssld.h"
#include "utils.h"


extern struct _config config;

static void rmspace(char *str);
static char *tolow(char *str);
//static void AddressToString(uint32_t ip, uint16_t port, char *buff);

void errorlog(char *message)
{
	if (config.daemon)
		syslog(LOG_DAEMON|LOG_ERR, message);
	else
	{
		fprintf(stderr, message);
		putchar('\n');
	}

	exit(EXIT_FAILURE);
}

/*static void AddressToString(uint32_t ip, uint16_t port, char *buff)
{
	struct in_addr addr;
	addr.s_addr = ip;
	sprintf(buff, "%s:%d", inet_ntoa(addr), (int) port);
}*/

static void rmspace(char *str)
{
	char	*buff = malloc((MAX_CONFIG_STR_LEN+1) * sizeof(char));
	register int	i, j = 0;

	for (i=0; str[i]; i++)
	{
		if (str[i] == '\\')
		{
			if (isspace(str[i+1]))
				buff[j++] = str[i+1];
			else if (str[i+1] == '\\')
				buff[j++] = str[i+1];
		}
		else if (!isspace(str[i]))
			buff[j++] = str[i];

		if (i >= MAX_CONFIG_STR_LEN)
			break;
	}

	buff[j] = '\0';
	
	strcpy(str, buff);
}

static char *tolow(char *str)
{
	register int	i=0;
	char	*buf = malloc((strlen(str)+1) * sizeof(char));
	
	while (str[i])
	{
		buf[i]=tolower(str[i]);
		i++;
	}
	buf[i] = '\0';

	return buf;
}

/*const char *SessionToString(const TcpSession *sess)
{
	static char buff[512];
	char addr1[32], addr2[32];

	addr1[0] = 0;
	addr2[0] = 0;

	AddressToString(sess->serverStream.ip_addr, sess->serverStream.port, addr1);
	AddressToString(sess->clientStream.ip_addr, sess->clientStream.port, addr2);

	sprintf(buff, "%s<->%s", addr1, addr2);
	return buff;
}
*/

/* Format and dump the data on the screen */
void DumpData(const u_char* data, uint32_t sz)
{
	register uint32_t i;

	for (i = 0; i < sz; i++)
	{
		if (isprint(data[i]) || data[i] == '\n' || data[i] == '\t' || data[i] == '\r') 
			putc(data[i], stdout);
		else
			putc('.', stdout);
	}
}

/* Getting MAC */
int getmac(const char *name, u_int8_t *mac)
{
	int ctl_sk = -1;
	int r;
	struct ifreq ifr;
	
	ctl_sk = socket(AF_INET, SOCK_DGRAM, 0);
	
	memset(&ifr,0,sizeof(struct ifreq));
	strcpy(ifr.ifr_name, name);
	r = ioctl(ctl_sk, SIOCGIFHWADDR, &ifr);
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6); 
	return r; 
}

/* for load config */
int load_config(const char *path, struct _config *config)
{
	char	strbuf[MAXSTRLEN];
	FILE	*fd = NULL;
	int		n = 0, line = 0, block = 0, index=0;
	
	fd = fopen(path, "r");
	
	if (fd == NULL)
	{
		fprintf(stderr, "ERROR: Can't open config file \"%s\".\n", path);
		return(-1);
	}

	while(!feof(fd))
	{
		register char	*p = strbuf;
		register char	*key = malloc((KEYLEN+1) * sizeof(char));
		register char	*val = malloc((VALLEN+1) * sizeof(char));
		char	title[TITLELEN];

		*key = '\0';
		*val = '\0';
		*title = '\0';

		line++;

		if (fgets(strbuf, sizeof(strbuf)-1, fd) == NULL)
			continue;

		rmspace(p);

		/* blank lines and comments get ignored */
		if (!*p || *p == '#')
			continue;

		if (p[0] == '[' && p[strlen(p)-1] == ']')
		{
			sscanf(p, "[%255[^]]", title);
			block = 1;
			index = config->index;

			config->cap[index] = malloc(sizeof(struct _cap));
			if (config->index == 0)
				memset(config->cap[index],0,sizeof(struct _cap));
			else
			{
				memcpy(config->cap[index],config->cap[index-1],sizeof(struct _cap));
				memset(config->cap[index],0,sizeof(struct _cap));
			}

			strcpy(config->cap[index]->title, title);

			config->cmdl=0;
			config->index++;
			continue;
		}

		/* parse */
		n = sscanf(p, "%255[^=\n\r\t]=%255[^\n\r\t]", key, val);

		if (n != 2)
		{
			fprintf(stderr, "ERROR: Can't parse config file %s at line %d.\n", path, line);
			continue;
		}
		
		key = tolow(key);

		if (!strcmp(key,"src"))
		{
			if (getmac(val, config->cap[index]->src_interface_mac) != -1)
				strcpy(config->cap[index]->src_interface, val);
			else
			{
				fprintf(stderr, "ERROR: %s fetching interface information error: Device not found.\n", val);
				return(-1);
			}
		}
		else if (!strcmp(key,"dst"))
		{
			if (getmac(val, config->cap[index]->dst_interface_mac) != -1)
				strcpy(config->cap[index]->dst_interface, val);
			else
			{
				fprintf(stderr, "ERROR: %s fetching interface information error: Device not found.\n", val);
				return(-1);
			}
		}
		else if (!strcmp(key,"ip"))
		{
			if (inet_aton(val, &config->cap[index]->server_ip) == 0)
			{
				fprintf(stderr, "Invalid IP address format \"%s\".\n", val);
				return(-1);
			}
		}
		else if (!strcmp(key,"port"))
		{
			config->cap[index]->port = (uint16_t) atoi(val);
			if (config->cap[index]->port == 0) // it will always < 65535 due to limited range of data type
			{
				fprintf(stderr, "Invalid TCP port value \"%d\".\n", config->cap[index]->port);
				return(-1);
			}
		}
		else if (!strcmp(key,"dsslport"))
                {
                        config->cap[index]->dsslport = (uint16_t) atoi(val);
                        if (config->cap[index]->dsslport == 0) // it will always < 65535 due to limited range of data type
                        {
                                fprintf(stderr, "Invalid TCP dsslport value \"%d\".\n", config->cap[index]->dsslport);
                                return(-1);
                        }
                }
		else if (!strcmp(key,"key"))
		{
			strcpy(config->cap[index]->keyfile, val);
		}
		else if (!strcmp(key,"pwd"))
		{
			strcpy(config->cap[index]->pwd, val);
		}
		// common options
		else if (!strcmp(key,"loglevel"))
		{
			if (block)
				fprintf(stderr,"WARNING: The option \"loglevel\" is common and must placed not in block \"[title]\".\n");
			config->loglevel = atoi(val);
		}
		else if (!strcmp(key,"daemon"))
		{
			if (block)
				fprintf(stderr,"WARNING: The option \"daemon\" is common and must placed not in block \"[title]\".\n");
			if (!strcmp(tolow(val),"off"))
				config->daemon = 0;
			else if (!strcmp(tolow(val),"on"))
				config->daemon = 1;
			else
				fprintf(stderr, "Invalid value in config in option \"%s\".\n", key);
		}
		else if (!strcmp(key,"pid"))
		{
			if (block)
				fprintf(stderr,"WARNING: The option \"pid\" is common and must placed not in block \"[title]\".\n");
			strcpy(config->pidfilename, val);
		}

		free(key);
		free(val);

	} // while

	fclose(fd);
	return(0);

}


void print_config(struct _config *cfg)
{
	int	index;

	puts  ("\n\t+---------------------------------------------------+");
	printf("\t| Common config                                     |\n");
	puts  ("\t+---------------------------------------------------+");
	printf("\t| Config file: %-37s|\n", cfg->config);
	printf("\t| PID file: %-40s|\n", cfg->pidfilename);
	printf("\t| loglevel: %-40d|\n", cfg->loglevel);
	printf("\t| daemon: %-42s|\n", cfg->daemon ? "on" : "off");
	printf("\t+---------------------------------------------------+\n\n\n");

	
	for (index=0; index<cfg->index; index++)
	{
		puts  ("\t+---------------------------------------------------+");
		printf("\t| Config capture %-35s|\n",cfg->cap[index]->title);
		puts  ("\t+---------------------------------------------------+");
		printf("\t| Keyfile: %-41s|\n", cfg->cap[index]->keyfile);
		printf("\t| Source Interface: %-32s|\n", cfg->cap[index]->src_interface);
		printf("\t| Destination Interface: %-27s|\n", cfg->cap[index]->dst_interface);
		printf("\t| Server IP address: %-31s|\n", inet_ntoa(cfg->cap[index]->server_ip));
		printf("\t| TCP Port: %-40d|\n",cfg->cap[index]->port);
                printf("\t| TCP DSSL Port: %-35d|\n",cfg->cap[index]->dsslport);
		printf("\t+---------------------------------------------------+\n\n");
	}

}

char *dssl_error(int n)
{
	switch(n)
	{
		case DSSL_E_OUT_OF_MEMORY:
			return("Out of memory");
/*		case DSSL_E_SSL_LOAD_CERTIFICATE:
			return("SSL certificate load error");*/
		case DSSL_E_SSL_LOAD_PRIVATE_KEY:
			return("SSL private key load error");
		case DSSL_E_SSL_UNKNOWN_VERSION:
			return("Unknown version of SSL");
		case DSSL_E_SSL_PROTOCOL_ERROR:
			return("SSL Protocol error");
		case DSSL_E_SSL_INVALID_RECORD_LENGTH:
			return("SSL Invalid record length");
		case DSSL_E_UNSPECIFIED_ERROR:
			return("Unspecified error");
		case DSSL_E_NOT_IMPL:
			return("Not IMPL");
		case DSSL_E_SSL_SERVER_KEY_UNKNOWN:
			return("SSL Server key unknown");
		case DSSL_E_SSL_CANNOT_DECRYPT:
			return("SSL: An undecryptable ciphersuite has been chosen");
		case DSSL_E_SSL_CORRUPTED_PMS:
			return("SSL: Invalid Pre Master Secret");
		case DSSL_E_SSL_PMS_VERSION_ROLLBACK:
			return("SSL: Protocol version rollback detected (SSL attack?)");
		case DSSL_E_SSL_DECRYPTION_ERROR:
			return("SSL: Generic decrytion error");
		case DSSL_E_SSL_BAD_FINISHED_DIGEST:
			return("SSL Protocol error: Bad Finished message digest");
		case DSSL_E_TCP_CANT_REASSEMBLE:
			return("TCP reassembly error");
		case DSSL_E_SSL_UNEXPECTED_TRANSMISSION:
			return("Unexpected transmission - session is already closed or aborted");
		case DSSL_E_SSL_INVALID_MAC:
			return("Message Authentification Code check failed");
		case DSSL_E_SSL_SESSION_NOT_IN_CACHE:
			return("Session renegotiation detected, but the previous session data is not cached - decryption impossible");
		case DSSL_E_SSL_PRIVATE_KEY_FILE_OPEN:
			return("Failed to open the private key file");
		case DSSL_E_SSL_INVALID_CERTIFICATE_RECORD:
			return("SSL Protocol error: invalid certificate list length");
		case DSSL_E_SSL_INVALID_CERTIFICATE_LENGTH:
			return("SSL Protocol error: invalid certificate length");
		case DSSL_E_SSL_BAD_CERTIFICATE:
			return("Bad server certificate detected");
		case DSSL_E_UNINITIALIZED_ARGUMENT:
			return("SSL: ephemeral keys cannot be decrypted");
		case DSSL_E_SSL_CANNOT_DECRYPT_EPHEMERAL:
			return("SSL: ephemeral keys cannot be decrypted");
		case DSSL_E_SSL_CANNOT_DECRYPT_NON_RSA:
			return("SSL: Only RSA keys can be used with viewssl");
		case DSSL_E_SSL_CERTIFICATE_KEY_MISMATCH:
			return("SSL: Server's certificate is signed with the key different than the one passed to CapEnvSetSSL_ServerInfo or DSSL_EnvSetServerInfo");
		case DSSL_E_UNSUPPORTED_COMPRESSION:
			return("viewssl unsupported compression");
		case DSSL_E_DECOMPRESSION_ERROR:
			return("decompression error");
		default:
			return("Unspecified error");
	}
}

int check_config(struct _config *cfg)
{
	register int	optchk = 0;
	int	index = 0;

	for(index = 0; index < cfg->index; index++) {
		if (strlen(cfg->cap[index]->src_interface) < 1)
		{
			if (cfg->cmdl)
				puts("Please, define source interface name: option \"-s\" (or \"--src-interface\") is obligatory.");
			else
				printf("Please, define source interface name: key \"src\" in config file in section [\"%s\"] is obligatory.",cfg->cap[index]->title);
			optchk = 1;
		}
	
		if (strlen(cfg->cap[index]->dst_interface) < 1)
		{
			if (cfg->cmdl)
				puts("Please, define destination interface name: option \"-d\" (or \"--dst-interface\") is obligatory.");
			else
				printf("Please, define destination interface name: key \"dst\" in config file in section [\"%s\"] is obligatory.",cfg->cap[index]->title);
			optchk = 1;
		}

		if( ( strcmp(cfg->cap[index]->dst_interface, cfg->cap[index]->src_interface) == 0 ) && ( cfg->cap[index]->dsslport == 0 ) )
                {
                        if (cfg->cmdl)
                                puts("Please, define DSSL port if source and destination interfaces are the same: option \"-D\" (or \"--dssl-port\").");
                        else
                                printf("Please, define DSSL port if source and destination interfaces are the same: key \"dsslport\" in config file in section [\"%s\"]",cfg->cap[index]->title);
                        optchk = 1;
                }


		if (cfg->cap[index]->server_ip.s_addr == 0)
		{
			if (cfg->cmdl)
				puts("Please, define server ip address: option \"-i\" (or \"--ip\") is obligatory.");
			else
				printf("Please, define source ip address: key \"ip\" in config file in section [\"%s\"] is obligatory.",cfg->cap[index]->title);
			optchk = 1;
		}

		if (cfg->cap[index]->port == 0)
		{
			if (cfg->cmdl)
				puts("Please, define port number: option \"-p\" (or \"--port\" is obligatory.");
			else
				printf("Please, define port number: key \"port\" in config file in section [\"%s\"] is obligatory.",cfg->cap[index]->title);
			optchk = 1;
		}

		if (strlen(cfg->cap[index]->keyfile) < 1)
		{
			if (cfg->cmdl)
				puts("Please, define keyfile path: option \"-k\" (or \"--key\") is obligatory.");
			else
				printf("Please, define keyfile path: key \"key\" in config file in section [\"%s\"] is obligatory.",cfg->cap[index]->title);
			optchk = 1;
		}
	}
	if (optchk)
		return(1);
	else
		return(0);
}

void usage (void)
{
	printf ("Usage: %s -c [config] | -l <interface> -k <key file> -n <server ip> -port <server port> -d <interface> [-w][-n][-v][-f][-h]\n" \
	"Available options:\n"
	"   --config (-c) [path]\t: viewssld config file.\n" \
	"   --key (-k) <path>\t: server's private key file path.\n" \
	"   --pwd (-w) <pass>\t: private key passphrase.\n" \
	"   --ip (-i) <ip addr>\t: server IP address.\n" \
	"   --port (-p) <port>\t: server port number. Port 443 is used if not specified directly.\n" \
        "   --dsslport (-D) <port>\t: port number to use for decrypted traffic. Port number specified by --port is used if not specified directly.\n" \
	"   --src-interface (-s) <interface> : capture and decrypt data from network link <interface>.\n" \
	"   --dst-interface (-d) <interface> : write decrypted data to network link <interface>.\n" \
	"   --no-daemon (-n)\t: do not daemonize (for debugging).\n" \
	"   --verbose (-v)\t: for verbose output.\n" \
	"   --pid file (-f)\t: for define alternate pid-file.\n" \
	"   --help (-h)\t\t: this help page.\n" \
	"   --version\t\t: print version info.\n\n" \
	, config.imagefile);
}

/*
* Get time as string
*/
char *gettime(void)
{
	time_t tm;
	time(&tm);
	return ctime(&tm);
}

/*
* Comand line arguments parsing
*/
int optparse(struct _config *config, char argc, char ** argv, char ** envp)
{
	int	option_index = 0;
	char	optac;
	int	longopt, rc = 0;

	struct option long_options[] = {
		{"version",0,&longopt,1},
		{"config",1,0,'c'},
		{"no-daemon",0,0,'n'},
		{"verbose",0,0,'v'},
		{"help",0,0,'h'},
		{"pid",1,0,'f'},
		{"key",1,0,'k'},
		{"pwd",1,0,'w'},
		{"port",1,0,'p'},
		{"dsslport",1,0,'D'},
		{"ip",1,0,'i'},
		{"src-interface",1,0,'s'},
		{"dst-interface",1,0,'d'},
		{0,0,0,0}
	};

	while ((optac = getopt_long (argc,argv,"vnhw:f:k:s:d:p:D:i:c::",long_options,&option_index)) != -1)
		switch (optac)
		{
			case 'c':
				if (optarg == NULL)
					strcpy(config->config, DEFAULT_CONFIG_FILE);
				else
					strcpy(config->config, optarg);

				if (load_config(config->config, config) == -1)
				{
					fprintf(stderr,"ERROR: Can't load config file \"%s\".", config->config);
					return(-1);
				}
				break;
			case 'v':
				config->loglevel = 1;
				break;
			case 'n':
				config->daemon = 0;
				break;
			case 'h':
				usage();
				return(1);
				break;
			case 'f':
				strcpy(config->pidfilename, optarg);
				break;
			case 0:
				if (longopt == 1)
				{
					versioninfo();
					exit(EXIT_SUCCESS);
				}
				longopt = 0;
				break;
			default:
			
				if (!config->cmdl)
				{
					usage();
					return(-1);
				}
				
				if (config->index == 0)
				{
					config->cap[0] = malloc(sizeof(struct _cap));
					memset(config->cap[0],0,sizeof(struct _cap));
					config->index=1;
				}
				
				switch (optac)
				{
					case 'k':
						strcpy(config->cap[0]->keyfile, optarg);
						break;
					case 'w':
						strcpy(config->cap[0]->pwd, optarg);
						break;
					case 's':
						if (getmac(optarg, config->cap[0]->src_interface_mac) != -1)
						{
							strcpy(config->cap[0]->src_interface, optarg);
						} else
						{
							fprintf(stderr,"ERROR: %s fetching interface information error: " \
							"Device not found.\n", optarg);
							return(-1);
						}
						break;
					case 'd':
						if (getmac(optarg, config->cap[0]->dst_interface_mac) != -1)
							strcpy(config->cap[0]->dst_interface, optarg);
						else
						{
							fprintf(stderr, "ERROR: %s fetching interface information error: " \
							"Device not found.\n", optarg);
							return(-1);
						}
						break;
					case 'p':
						config->cap[0]->port = (uint16_t) atoi(optarg);
						if (config->cap[0]->port == 0) // it will always < 65535 due to limited range of data type
						{ 
							fprintf(stderr, "Invalid TCP port value \"%d\".\n", \
							config->cap[0]->port);
							return(-1);
						}
						break;
					 case 'D':
                                                config->cap[0]->dsslport = (uint16_t) atoi(optarg);
                                                if (config->cap[0]->dsslport == 0) // it will always < 65535 due to limited range of data type
                                                {
                                                        fprintf(stderr, "Invalid DSSL TCP port value \"%d\".\n", \
                                                        config->cap[0]->dsslport);
                                                        return(-1);
                                                }
                                                break;
					case 'i':
						if (inet_aton(optarg, &config->cap[0]->server_ip) == 0)
						{
							fprintf(stderr, "Invalid IP address format \"%s\".\n", optarg);
							return(-1);
						}
						break;
					default:
						usage();
						return(-1);
				}
				

			break;
		}
		return(0);
}


void versioninfo(void)
{
	printf("viewssld version %s\n" \
		   "Build-Date: %s %s\n" \
		   ,PACKAGE_VERSION,__DATE__,__TIME__);
}
