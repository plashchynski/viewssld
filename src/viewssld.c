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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <openssl/ssl.h>
#include <pcap.h>
#include <dssl/sslcap.h>

#include "viewssld.h"
#include "utils.h"

struct _config	config;
static struct _errorbuf errbuf;
static struct _childs	childs;

static void before_exit(void);
static void fsignal(int sig);
static int proceed(void);
static void session_event_handler(CapEnv* env, TcpSession* sess, char event);
static void data_callback_proc(NM_PacketDir dir, void* user_data, u_char* pkt_payload, uint32_t pkt_size, DSSL_Pkt* last_packet);
static void error_callback_proc(void* user_data, int error_code);
static void SIGCHLD_act(int signal, siginfo_t *siginfo, void *hz);
int sendEmptyTCPSegment( libnet_t *libnet_c, TcpSession *sess, u_int32_t seq, u_int32_t ack, u_int8_t control, NM_PacketDir dir );

#define MISSING_PACKET_COUNT    100
#define MISSING_PACKET_TIMEOUT  10

static int	parent;
static int	capindex;

int main(int argc, char *argv[], char *envp[])
{
	register int		i=0; // for counter
	int		rc = 0;
	char 	*logtitle;	// for syslog title
	pid_t	pid;

	// Initialization area
	config.loglevel = 0;
	config.daemon = 1;
	config.cmdl = 1;
	config.index = 0;

	strcpy(config.pidfilename, DEFAULT_PID_FILE);
	strcpy(config.imagefile, argv[0]);

	// Initialize buffers for errors
	*errbuf.common = '\0';
	*errbuf.libnet = '\0';
	capindex = 0;

	if ((rc = optparse(&config, argc, argv, envp)) != 0)
	switch (rc)
	{
		case -1:
			exit(EXIT_FAILURE);
		case 1:
			exit(EXIT_SUCCESS);
		default:
			exit(rc);
	}
	
	if (config.index == 0)
	{
		fprintf(stderr,"You must define all obligatory parameters in running arguments or in configuration file.\n");
		usage();
		exit(EXIT_FAILURE);
	}
	
	if (check_config(&config))
		exit (EXIT_FAILURE);
		
	if (config.loglevel > 0)
		print_config(&config);
		
	if (getuid() != 0)
	{
		fprintf(stderr, "%s, you must be root to run this program.\n", getlogin());
		exit (EXIT_FAILURE);
	}

	config.pidfile = fopen (config.pidfilename, "w");
	if (config.pidfile == NULL)
	{
		fprintf (stderr, "Error to create pid-file \"%s\".\n", config.pidfilename);
		fprintf (stderr, "Try %s -f <path>", config.imagefile);
		exit (EXIT_FAILURE);
	}

	if (config.daemon)
	{
		if (daemon(1,1) != 0)
		{
			fprintf(stderr,"Daemonize error, running in interactive mode.\n");
			config.daemon = 0;
		}
	}
	
	// Write PID to PID-file
	fprintf(config.pidfile, "%d\n", getpid());
	fclose(config.pidfile);

	atexit(before_exit);

	if (config.index > 1)
	{
		struct	sigaction sact;
		
		sact.sa_sigaction = SIGCHLD_act;
		sact.sa_flags = SA_RESTART | SA_NOMASK | SA_SIGINFO;
		sigaction(SIGCHLD, &sact, NULL);
	
		childs.index = 0;
		parent = 1;
		for (i=0; i<config.index; i++)
		{
			pid = fork();
			switch(pid)
			{
				case -1: // fork() error
					errorlog("ERROR: Can't exec fork().");
					break;

				case 0:	// in child
					logtitle = malloc((strlen(config.cap[i]->title)+24) * sizeof(char));
					parent = 0;
					capindex = i;
				
					sprintf(logtitle, "viewssl daemon child [%s]", config.cap[capindex]->title);

					openlog(logtitle, LOG_PID, LOG_DAEMON);
					syslog(LOG_NOTICE,"started at %s",gettime());
					break;

				default: // in parent
					childs.pid[childs.index] = pid;
					childs.title[childs.index] = malloc((strlen(config.cap[childs.index]->title)+1)*sizeof(char));
					strcpy(childs.title[childs.index],config.cap[childs.index]->title);
					childs.index++;
					break;
			} // switch(pid)

			if (!parent)
				break;
		} // for (i=0;i<config.index;i++)

		signal(SIGTERM, fsignal);
		signal(SIGINT, fsignal);
		signal(SIGQUIT, fsignal);


		if (parent)
		{ // in parent
			struct	sockaddr_un uds_addr;
			struct  sockaddr_un cl_addr;

			int		ss=0, r=0;	// master services socket

			// Master
			openlog("viewssl daemon master", LOG_PID, LOG_DAEMON);
			syslog(LOG_NOTICE, "started at %s", gettime());
			
			ss = socket(PF_UNIX, SOCK_STREAM, 0);
			if (ss < 0)
				errorlog("socket() error.");

			
			memset(&uds_addr, 0, sizeof(uds_addr));
			uds_addr.sun_family = AF_UNIX;
			strcpy(uds_addr.sun_path,SOCKPATH);
			
			unlink (SOCKPATH);
			
			r = bind(ss, (struct sockaddr *)&uds_addr, sizeof(uds_addr));
			if (r < 0)
				errorlog("bind() error.");
			
			r = listen(ss, 10);
			if (r < 0)
				errorlog("listen() error.");
			
			while(1)
			{
				int	cons=0;
				socklen_t cl_addr_len=0;

				memset (&cl_addr, 0, sizeof(cl_addr));
				cons = accept(ss, (struct sockaddr*) &cl_addr, &cl_addr_len);
				close(cons);
			}

			close(ss);
			unlink (SOCKPATH);
			exit(EXIT_SUCCESS);	// end master

		} else // child
		{
			signal(SIGCHLD, fsignal);
		}
		
	} // if (config.index > 1)
	else
	{ // one thread
		openlog("viewssl daemon", LOG_PID, LOG_DAEMON);
	}
	
	SSL_library_init();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();

	rc = proceed();

	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();

	if (rc != 0)
		exit(EXIT_FAILURE);
	else
		exit(EXIT_SUCCESS);	// end childs
}

static void SIGCHLD_act(int signal, siginfo_t *siginfo, void *hz)
{
	register int	j;

	if (signal != SIGCHLD)
		return;
 
	for (j=0; j<childs.index; j++)
		if (childs.pid[j] == siginfo->si_pid)
			break;

	if (j != childs.index)
		syslog(LOG_NOTICE, "child [%s] has been stopped at %s", childs.title[j], gettime());
	else
		syslog(LOG_NOTICE, "child pid - %d has been stopped at %s", siginfo->si_pid, gettime());

	waitpid(siginfo->si_pid, NULL, 0);
}

/*
Signals handler
*/
static void fsignal(int sig)
{
	register int	i=0;

	switch(sig)
	{
		case SIGTERM:
		case SIGINT:
		case SIGQUIT:
			if (parent)
			{
				for (i=0;i<childs.index;i++)
					kill(childs.pid[i],SIGTERM);

					unlink(config.pidfilename);
					unlink(SOCKPATH);
			}
		
			syslog(LOG_NOTICE, "stopped on signal %d at %s", sig, gettime());
			closelog();
			_exit(EXIT_SUCCESS);
			break;
		default:
			syslog(LOG_NOTICE,"got signal %d. ignore...",sig);
			break;
	}
}

static void	before_exit(void) // atexit handler
{
	syslog(LOG_NOTICE, "stopped on exit() at %s", gettime());
	unlink(config.pidfilename);
}

static int proceed(void)
{
	pcap_t* p = NULL;
	CapEnv* env = NULL;
	int rc = 0;
	struct bpf_program fp;		/* The compiled filter expression */
	char filter_exp[1024];

	p = pcap_open_live(config.cap[capindex]->src_interface, 1550, 1, 500, errbuf.common);
	if (!p)
	{
		if (config.daemon)
			syslog(LOG_CRIT, "pcap_open_live error: %s", errbuf.common);
		else
			fprintf(stderr, "ERROR: pcap_open_live error: %s\n", errbuf.common);
		return(-1);
	}

	sprintf( filter_exp, "ip host %s and tcp port %d",  inet_ntoa(config.cap[capindex]->server_ip), config.cap[capindex]->port );

	if (pcap_compile(p, &fp, filter_exp, 0, 0) == -1) 
	{
		 fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(p));
		 return(-1);
	}
	if (pcap_setfilter(p, &fp) == -1) 
	{
		 fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(p));
		 return(-1);
	 }

	env = CapEnvCreate(p, 255, 0, 0);

	rc = CapEnvSetSSL_ServerInfo(env, &config.cap[capindex]->server_ip, config.cap[capindex]->port, 
					config.cap[capindex]->keyfile, config.cap[capindex]->pwd);

	if (rc != 0)
	{
		if (config.daemon)
			syslog(LOG_CRIT, "CapEnvSetSSL_ServerInfo() failed, code %d: %s", \
			rc, dssl_error(rc));
		else
			fprintf(stderr,"ERROR: CapEnvSetSSL_ServerInfo() failed, code %d.\n", rc);
		return(-1);
	}

	CapEnvSetSessionCallback(env, session_event_handler, NULL);

	rc = CapEnvCapture(env);
	if (rc != 0)
	{
		if (config.daemon)
			syslog(LOG_CRIT, "CapEnvCapture() failed.");
		else
			fprintf(stderr,"CapEnvCapture() failed.\n");
		return(-1);
	}

	if (env)
	{
		CapEnvDestroy(env);
		env = NULL;
	}

	if (p)
	{
		pcap_close(p);
		p = NULL;
	}

	return(rc);
}

// Missing packet handler
static int missing_packet_callback(NM_PacketDir dir, void* user_data, uint32_t pkt_seq, uint32_t pkt_size)
{
	if (config.daemon)
		syslog(LOG_CRIT, "Missing packet(s) detected.");
	else		
		fprintf(stderr,"Missing packet(s) detected; missing segment size %u", pkt_size);
	
	return 1; /* skip and continue */
}

// TCP session state for fake stream of decrypted packets
typedef struct _FakeSessionState
{
	u_int32_t	clientSeq;
	u_int32_t	serverSeq;
	u_int8_t	handshakeSent;
	libnet_t*	ln;		// libnet context
} FakeSessionState;

// Initialise fake TCP session state
int init_fake_session_state( FakeSessionState*	fakeSess )
{
	// Init libnet context
        fakeSess->ln = libnet_init(
                  LIBNET_LINK,
                  config.cap[capindex]->dst_interface,
                  errbuf.libnet
        );

        if( fakeSess->ln == NULL )
        {
        	if (config.daemon)
                	syslog(LOG_ERR, "error opening libnet context: %s", errbuf.libnet);
                else
                        fprintf(stderr, "Error opening libnet context: %s.\n", errbuf.libnet);

                return( -1 );
        }

	if( libnet_seed_prand( fakeSess->ln ) == -1 )
	{
		 if (config.daemon)
                        syslog(LOG_ERR, "error seeding libnet prand: %s", errbuf.libnet);
                else
                        fprintf(stderr, "Error seeding libnet prand: %s.\n", errbuf.libnet);

		libnet_destroy( fakeSess->ln );
		return( -1 );		
	}

	// Initialise other member variables
	fakeSess->handshakeSent = 0;
	fakeSess->clientSeq = libnet_get_prand (LIBNET_PRu16);
        fakeSess->serverSeq = libnet_get_prand (LIBNET_PRu16);

	return( 1 );
}

// Handles session startup and teardown
static void session_event_handler(CapEnv* env, TcpSession* sess, char event)
{
	char buff[512];
	SessionToString(sess, buff);
	FakeSessionState*	mySession;

	switch(event)
	{
		case DSSL_EVENT_NEW_SESSION:
			if (config.loglevel > 0)
			{
				if (config.daemon)
					syslog(LOG_INFO, "=> New Session: %s", buff);
				else
					fprintf(stderr, "\n=> New Session: %s", buff);
			}

		        if( ( mySession = malloc( sizeof( FakeSessionState ) ) ) != NULL )
		        {
				if( init_fake_session_state( mySession ) != -1 )
				{
					SessionSetCallback(sess, data_callback_proc, error_callback_proc, sess);
					sess->user_data = mySession;
					SessionSetMissingPacketCallback( sess, missing_packet_callback, MISSING_PACKET_COUNT, 
						MISSING_PACKET_TIMEOUT );
				}
				else
				{
					if (config.loglevel > 0)
	                                {
	                                        if (config.daemon)
	                                                syslog(LOG_INFO, "error: cannot init fake session: %s", buff);
	                                        else
	                                                fprintf(stderr, "Error: cannot init fake session: %s", buff);
	                                }
				}
			}
			else
			{
				if (config.loglevel > 0)
	                        {
                                	if (config.daemon)
                                        	syslog(LOG_INFO, "error: cannot allocate memory for fake session: %s", buff);
	                                else
	                                        fprintf(stderr, "Error: cannot allocate memory for fake session: %s", buff);
				}
                        }

			break;

		case DSSL_EVENT_SESSION_CLOSING:
			if (config.loglevel > 0)
			{
				// Get stats
				struct pcap_stat        myStats;
	                        pcap_stats(env->pcap_adapter, &myStats);

				if (config.daemon)
					syslog(LOG_INFO, "<= Session closing: %s\tpkts recv: %d pkts drop: %d", buff, myStats.ps_recv, myStats.ps_drop );
				else
					fprintf(stderr, "\n<= Session closing: %s\tpkts recv: %d pkts drop: %d", buff, myStats.ps_recv, myStats.ps_drop );
			}
			// Terminate session
			mySession = (FakeSessionState*)sess->user_data;
			if( mySession->handshakeSent )
				sendEmptyTCPSegment( mySession->ln, sess, mySession->serverSeq, mySession->clientSeq, TH_RST | TH_ACK, ePacketDirFromServer );
			// Clean up libnet and fake session object
			libnet_destroy( mySession->ln );
			free( sess->user_data );
			break;

		default:
			if (config.daemon)
				syslog(LOG_ERR, "unknown session event code (%d).", (int)event);
			else
				fprintf(stderr, "ERROR: Unknown session event code (%d).\n", (int)event);
			break;
	}
}

// Sends an empty TCP segment with the specified parameters
int sendEmptyTCPSegment( libnet_t               *libnet_c, 
			 TcpSession             *sess,
			 u_int32_t		seq,
			 u_int32_t		ack,
			 u_int8_t		control,
			 NM_PacketDir		dir )
{
	libnet_ptag_t   tcp, ip, ethernet;
	tcp = ip = ethernet = 0;

	tcp = libnet_build_tcp(
         	( dir == ePacketDirFromClient ) ? sess->clientStream.port : ( config.cap[capindex]->dsslport ? config.cap[capindex]->dsslport: sess->serverStream.port ),    /* source port */
                ( dir == ePacketDirFromClient ) ? ( config.cap[capindex]->dsslport ? config.cap[capindex]->dsslport: sess->serverStream.port ) : sess->clientStream.port,    /* destination port */
                seq,                                  		/* sequence number */
                ack,                                            /* acknowledgement num */
                control,                                        /* control flags */
                32767,                                          /* window size */
                0,                                              /* checksum */
                10,                                             /* urgent pointer */
                LIBNET_TCP_H,                  			/* TCP packet size */
                NULL,		                                /* payload */
                0,		                                /* payload size */
                libnet_c,                                       /* libnet handle */
                0);	                                        /* libnet id */

        if (tcp == -1)
        {
                if (config.daemon)
                         syslog(LOG_ERR, "Can't build TCP header: %s", libnet_geterror(libnet_c));
                else
                        fprintf(stderr, "Can't build TCP header: %s.\n", libnet_geterror(libnet_c));
		return( -1 );
        }
                
	ip = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_TCP_H,  					/* length */
		0,                                              /* TOS */
		54609,                                            /* IP ID */
		0,                                              /* IP Frag */
		64,                                             /* TTL */
		IPPROTO_TCP,                                    /* protocol */
		0,                                              /* checksum */
		( dir == ePacketDirFromClient ) ? sess->clientStream.ip_addr : sess->serverStream.ip_addr,      /* source IP */
		( dir == ePacketDirFromClient ) ? sess->serverStream.ip_addr : sess->clientStream.ip_addr,      /* destination IP */
		NULL,                                           /* payload */
		0,                                              /* payload size */
		libnet_c,                                       /* libnet handle */
		0);                                             /* libnet id */

	if (ip == -1)
	{
		if (config.daemon)
			syslog(LOG_ERR, "Can't build IP header: %s", libnet_geterror(libnet_c));
		else
			fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(libnet_c));
		return( -1 );
	}
	
	ethernet = libnet_build_ethernet(
		( dir == ePacketDirFromClient ) ? config.cap[capindex]->dst_interface_mac : config.cap[capindex]->src_interface_mac, /* ethernet dest */
		( dir == ePacketDirFromClient ) ? config.cap[capindex]->src_interface_mac : config.cap[capindex]->dst_interface_mac, /* ethernet source */
		ETHERTYPE_IP,           /* protocol type */
		NULL,                   /* payload */
		0,                      /* payload size */
		libnet_c,               /* libnet handle */
		0);                     /* libnet id */

	if (ethernet == -1)
	{
		if (config.daemon)
			syslog(LOG_ERR, "Can't build ethernet header: %s", libnet_geterror(libnet_c));
		else
			fprintf(stderr, "Can't build ethernet header: %s.\n", libnet_geterror(libnet_c));
		return( -1 );
	}

	if (libnet_write(libnet_c) == -1)
	{
		if (config.daemon)
			syslog(LOG_ERR, "write error: %s", libnet_geterror(libnet_c));
		else
			fprintf(stderr, "Write error: %s.\n", libnet_geterror(libnet_c));
		return( -1 );
	}
	
	libnet_clear_packet(libnet_c);

	return( 1 );
}

// Sends a SYN/SYN-ACK/ACK triplet
int sendTCPHandshake( libnet_t               *libnet_c,
                      TcpSession             *sess,
		      FakeSessionState       *mySession )
{
	if( sendEmptyTCPSegment( libnet_c, sess, mySession->clientSeq, 0, TH_SYN, ePacketDirFromClient ) == -1 )
		return( -1 );
	mySession->clientSeq++;
	if ( sendEmptyTCPSegment( libnet_c, sess, mySession->serverSeq, mySession->clientSeq, TH_SYN | TH_ACK, ePacketDirFromServer ) == -1 )
		return( -1 );
	mySession->serverSeq++;
	if( sendEmptyTCPSegment( libnet_c, sess, mySession->clientSeq, mySession->serverSeq, TH_ACK, ePacketDirFromClient ) == -1 )
		return( -1 );

	return( 1 );
}

// Handles decrypted data from libdssl
static void data_callback_proc(NM_PacketDir dir, void* user_data, u_char* pkt_payload, uint32_t pkt_size, DSSL_Pkt* last_packet)
{
	libnet_ptag_t		tcp, ip, ethernet;
	register libnet_t	*libnet_c;
	TcpSession		*sess = (TcpSession*) user_data;
	uint32_t		bytes_written, bytes_to_write;
	u_char*			payload_ptr;
	FakeSessionState	*mySession = (FakeSessionState*) sess->user_data;

	// Initialise byte counter and payload pointer
	bytes_written = 0;
	payload_ptr = pkt_payload;
	tcp = ip = ethernet = 0;

	if (config.loglevel > 0 && !config.daemon)
	{
		switch(dir)
		{
			case ePacketDirFromClient:
				fprintf(stderr, "\nC->S: %d bytes\n", pkt_size );
				break;
			case ePacketDirFromServer:
				fprintf(stderr, "S->C: %d bytes\n", pkt_size );
				break;
			default:
				fprintf(stderr, "\nUnknown packet direction!");
				break;
		}
	}

        // Get libnet context
        libnet_c = mySession->ln;

	// Send handshake if necessary
        if( mySession->handshakeSent == 0 )
        {
		sendTCPHandshake( libnet_c, sess, mySession );
		mySession->handshakeSent = 1;
	}

	// Split pkt_payload into a 1460 byte MSS
	while( bytes_written < pkt_size )
	{
		// Work out how many bytes to write on this pass
		bytes_to_write = ( ( pkt_size - bytes_written ) < 1460 ) ? ( pkt_size - bytes_written ) : 1460;

		tcp = libnet_build_tcp(
			( dir == ePacketDirFromClient ) ? sess->clientStream.port : ( config.cap[capindex]->dsslport ? config.cap[capindex]->dsslport: sess->serverStream.port ),	/* source port */
			( dir == ePacketDirFromClient ) ? ( config.cap[capindex]->dsslport ? config.cap[capindex]->dsslport: sess->serverStream.port ) : sess->clientStream.port,	/* destination port */
			( dir == ePacketDirFromClient ) ? mySession->clientSeq : mySession->serverSeq,		/* sequence number */
			( dir == ePacketDirFromClient ) ? mySession->serverSeq : mySession->clientSeq,		/* acknowledgement num */
			TH_ACK,						/* control flags */
			32767,						/* window size */
			0,						/* checksum */
			10,						/* urgent pointer */
			LIBNET_TCP_H + bytes_to_write,			/* TCP packet size */
			payload_ptr,					/* payload */
			bytes_to_write,					/* payload size */
			libnet_c,					/* libnet handle */
			0);						/* libnet id */

		// Increment count of bytes written
                bytes_written += bytes_to_write;
		if( dir == ePacketDirFromClient ) 
			mySession->clientSeq += bytes_to_write;
		else
			mySession->serverSeq += bytes_to_write;

                // Increment payload_ptr
                payload_ptr += bytes_to_write;

		if (tcp == -1)
		{
			if (config.daemon)
				syslog(LOG_ERR, "Can't build TCP header: %s", libnet_geterror(libnet_c));
			else
				fprintf(stderr, "Can't build TCP header: %s.\n", libnet_geterror(libnet_c));
		}
		else
		{
			ip = libnet_build_ipv4(
				LIBNET_IPV4_H + LIBNET_TCP_H + bytes_to_write,	/* length */
				0,						/* TOS */
				54609,						/* IP ID */
				0,						/* IP Frag */
				64,						/* TTL */
				IPPROTO_TCP,					/* protocol */
				0,						/* checksum */
				( dir == ePacketDirFromClient ) ? sess->clientStream.ip_addr : sess->serverStream.ip_addr,	/* source IP */
				( dir == ePacketDirFromClient ) ? sess->serverStream.ip_addr : sess->clientStream.ip_addr,	/* destination IP */
				NULL,						/* payload */
				0,						/* payload size */
				libnet_c,					/* libnet handle */
				0);						/* libnet id */
	
			if (ip == -1)
			{
				if (config.daemon)
					syslog(LOG_ERR, "Can't build IP header: %s", libnet_geterror(libnet_c));
				else
					fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(libnet_c));					
			}
			else
			{
				ethernet = libnet_build_ethernet(
					( dir == ePacketDirFromClient ) ? config.cap[capindex]->dst_interface_mac : config.cap[capindex]->src_interface_mac,	/* ethernet destination */
					( dir == ePacketDirFromClient ) ? config.cap[capindex]->src_interface_mac : config.cap[capindex]->dst_interface_mac,	/* ethernet source */
					ETHERTYPE_IP,		/* protocol type */
					NULL,			/* payload */
					0,			/* payload size */
					libnet_c,		/* libnet handle */
					0);			/* libnet id */
		
				if (ethernet == -1)
				{
					if (config.daemon)
						syslog(LOG_ERR, "Can't build ethernet header: %s", libnet_geterror(libnet_c));
					else
						fprintf(stderr, "Can't build ethernet header: %s.\n", libnet_geterror(libnet_c));
				}
				else
				{
					if (libnet_write(libnet_c) == -1)
					{
						if (config.daemon)
							syslog(LOG_ERR, "write error: %s", libnet_geterror(libnet_c));
						else
							fprintf(stderr, "Write error: %s.\n", libnet_geterror(libnet_c));
					}
				}
			}
		}
		libnet_clear_packet(libnet_c);
	}
}

// Error handler
static void error_callback_proc(void* user_data, int error_code)
{
	if (config.loglevel > 0)
	{
		TcpSession* sess = (TcpSession*) user_data;
	        char buff[512];
	        SessionToString(sess, buff);
	
		if (config.daemon)
		{
			syslog(LOG_ERR, "SSL session: %s, error code: %d: %s", \
			buff, error_code, dssl_error(error_code));
		}
		else
		{
			fprintf(stderr, "\nERROR: SSL session: %s, error code: %d: %s.\n", \
			buff, error_code, dssl_error(error_code));
		}
	}
}
