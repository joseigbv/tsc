
/******************************
* simple tcp port scan (no threads)
*
* linux: gcc -Wall -O2 tsc.c -o tsc  
* osx: gcc -Wall -O2 tsc.c -o tsc
* win32: gcc -Wall -O2 tsc.c -o tsc -lwsock32
* solaris: gcc -Wall -O2 tsc.c -o tsc -lsocket -lnsl
*
*******************************/

#ifdef WIN32

#include <windows.h>
#include <winsock.h>

#define ETIMEDOUT WSAETIMEDOUT
#define ECONNREFUSED WSAECONNREFUSED

#else 

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>


/*************************
 * parametrizacion
 *************************/

// configuracion
#define MAX_CON 1000 // concurrencia (linux, win32 -> 1000, osx, solaris -> 100)
#define WAIT 10 // entre bloque peticiones (ej. 10 ms)
#define TIMEOUT_CONN 200 // timeout conexion (ej. 200 ms) 
#define TIMEOUT_RW 2000 // timeout lectura / escritura (ej. 5000 ms) 
#define VERBOSE 0 // modo verboso ;)

// tamanio buffers
#define SZ_SBUF	1024
#define SZ_HOST 24
#ifdef WIN32
#define SZ_BANNER 25
#else
#define SZ_BANNER 40
#endif

// puertos por defecto (mios)
u_short DEFAULT_PORTS[] = 
{ 
	21, 22, 23, 25, 53, 79, 80, 88, 106, 110, 111, 135, 137, 138, 139, 143, 
	161, 162, 389, 443, 445, 465, 500, 512, 513, 514, 587, 593, 636, 901, 993, 1024, 1025, 1080, 
	1241, 1433, 1434, 1723, 1812, 2000, 2049, 2601, 2605, 3306, 3128, 3389, 5060, 5353, 
	5432, 5666, 5800, 5900, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 
	6008, 6009, 6010, 6667, 8000, 8080, 8443, 8834, 10000, 10001, 10002, 
	10003, 10004, 10005, 10006, 10007, 10008, 10009, 10010 
};


/***************************
* tipos, variables globales, etc.
****************************/

// posibles estados conexion
#define X_PENDING 0x01
#define X_CONNECTED 0x02
#define X_PENDING_RECV 0x03
#define X_RECV 0x04
#define X_PENDING_SEND 0x05
#define X_SEND 0x06
#define X_CANCELLED 0x07
#define X_TIMEOUT 0x08
#define X_REFUSED 0x09
#define X_CLOSED 0x0a
#define X_ERROR 0xff

#ifdef WIN32
typedef uint32_t socklen_t;
#endif 

// tipo scan line host:port
typedef struct 
{
	char host[SZ_HOST];
	struct in_addr addr;
	u_short port;
	int status;
	int socket;
	double start;

} t_sl;

// lista host:port 
t_sl *sl;
int sz_sl;


/*************************
 * funciones
 *************************/

// mensaje de error y salimos
void x_abort(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}


// copia con final nulo
char *x_strncpy(char *s1, char *s2, int sz)
{
	char *r = NULL;

	if (sz) 
	{
		r = strncpy(s1, s2, sz);
		s1[sz - 1] = 0;
	}

	return r;
}


// asignacion memoria con control error
void *x_malloc(size_t sz)
{
	void *p;

	if (! (p = malloc(sz)))
		x_abort("malloc error");

	return p;
}


// devuelve milisegundos desde 1/1/70
double crono()
{
	struct timeval tim;

	// fecha en timeval
	gettimeofday(&tim, 0);

	return ((tim.tv_sec * 1000000) + 
		tim.tv_usec) / 1000;
}


// limpiamos banner
char *clean_txt(char *s, int sz)
{
	int i;

	// quita caracteres no impr
	for (i = 0; i < sz - 1; i++) 
		s[i] = (s[i] < 32 || s[i] > 126 ? '.' : s[i]);

	// fin nulo
	s[i] = 0;

	return s;
}


// intento establecimiento de conexion 
int init_conn(struct in_addr addr, u_short port, int *sock)
{
	struct sockaddr_in sa; 
	int r = X_ERROR;
	unsigned long arg;
	
	// creamos socket
	if ((*sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
		x_abort("socket error");

	else
	{
		// sin bloqueo
#ifdef WIN32
		arg = 1; 
		ioctlsocket(*sock, FIONBIO, &arg);
#else
		arg = fcntl(*sock, F_GETFL, 0); 
		fcntl(*sock, F_SETFL, arg |= O_NONBLOCK); 
#endif 

		// estructura server_addr
		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_port = htons(port);
		sa.sin_addr = addr;

		// intentamos conectar
		if (connect(*sock, (struct sockaddr *)&sa, sizeof(sa)) == -1) 
		{
			// error o en espera ?
#ifdef WIN32
			r = WSAGetLastError() == WSAEWOULDBLOCK ? 
				X_PENDING : X_ERROR;
#else
                        // error o en espera ?
                        switch (errno)
                        {
                                case EINPROGRESS: r = X_PENDING; break;
                                case ETIMEDOUT: r = X_TIMEOUT; break;
                                case ECONNREFUSED: r = X_REFUSED; break;

                                default: r = X_ERROR;
                        }
#endif
		}

		// todo ha ido bien
		else r = X_CONNECTED;
	}

	// si todo ha ido bien
	return r;
}


// aux select (nfd -> r=0, w=1)
int x_select(int sock, int nfd)
{
	int r;
	struct timeval tv;
	fd_set fd; 

	// init params
	tv.tv_sec = 0; tv.tv_usec = 0; 
	FD_ZERO(&fd); FD_SET(sock, &fd); 

	// select
	r = nfd ? select(sock + 1, 0, &fd, 0, &tv) :
		select(sock + 1, &fd, 0, 0, &tv);
	
	return r;
}


// check de connexiones pendientes
int check_conn(int sock)
{
	int r;
	int v; 

#ifdef WIN32
	int sz;
#else
	socklen_t sz; 
#endif
	
	// definimos timeout de conexion
	switch ((r = x_select(sock, 1)))
	{
		case -1: r = X_ERROR; break; 
		case  0: r = X_PENDING; break;

		// socket listo 
		default: 

			sz = sizeof(int);

			// conectado ?
			if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&v, &sz) == -1) 
				x_abort("getsockopt error!");

			// valor devuelto?
			switch (v) 
			{
				case 0: r = X_CONNECTED; break;
				case ETIMEDOUT: r = X_TIMEOUT; break;
				case ECONNREFUSED: r = X_REFUSED; break;

				default: r = X_ERROR; 
			}
	}

	return r;
}


// desconexion 
void close_conn(int sock) 
{ 
	struct linger l; 

	// evita TIME_WAIT
	l.l_onoff = 1; l.l_linger = 0;
	setsockopt(sock, SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof(l));

	// cierra socket
#ifdef WIN32
	closesocket(sock);
#else
	close(sock); 
#endif
}


// respuesta
int try_recv(int sock, char *sbuf, int *sz)
{
	int r; 

	// init  datos
	memset(sbuf, 0, *sz);
		
	// si socket listo
	switch (r = x_select(sock, 0))
	{
		case -1: r = X_ERROR; break;
		case  0: r = X_PENDING_RECV; break;
		
		default: 

			// leemos datos
			if ((*sz = recv(sock, sbuf, *sz, 0)) == -1)
				r = X_ERROR;

			else r = X_RECV;
	}

	return r;
}


// envio  datos socket
int try_send(int sock, const char *sbuf, int sz)
{
	int r; 

	// si socket listo
	switch (r = x_select(sock, 1))
	{
		case -1: r = X_ERROR; break;
		case  0: r = X_PENDING_SEND; break;

		default: 

			// enviamos datos
			if ((sz = send(sock, sbuf, sz, 0)) == -1)
				r = X_ERROR;

			else r = X_SEND;
	}

	return r;
}


// leemos hostnames de fichero de texto
int read_hosts(const char *fname, char **hosts[], char **sbuf)
{
	int f, sz = 0;
	char *p, *s;
	struct stat st;

	// tamanio fichero?
	if ((stat(fname, &st) != -1) && (f = open(fname, O_RDONLY)))
	{
		if (st.st_size) 
		{
			// reservamos memoria
			*sbuf = p = (char *)x_malloc(st.st_size);

			// leemos contenido
			read(f, *sbuf, st.st_size);

			// contamos el numero de hosts
			while (*p) if (*p++ == '\n') sz++; sz++;

			// reservamos memoria
			*hosts = (char **)x_malloc(sz * sizeof(char *));

			// contamos lineas y saltamos comments o vacios
			for (p = *sbuf, sz = 0; (s = strtok(p, "\n")); p = NULL)
				if (*s != '\0' && *s != '#') (*hosts)[sz++] = s;
		}

		// cerramos fichero
		close(f);
	}
	
	return sz;
}


// calculamos ips a partir de red (formato cidr)
int calc_ips(const char *cidr, char **hosts[], char **sbuf)
{
	char s[5], *p;
	unsigned int cnt, net;
	int o[4], m, i = 0, j = 0;

	while (*cidr)
	{
		switch (*cidr)
		{
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':

				// numero 
				if (j > 3) return 0;
				s[j++] = *cidr;

				break;

			case '.':
			case '/':
			
				// procesamos octeto
				if (i > 3 || j > 3) return 0;
				j = s[j] = 0;
				if ((o[i++] = atoi(s)) > 255) return 0;

				break;

			default: return 0;
		}

		cidr++;
	}

	// calculamos mask
	j = s[j] = 0; 
	if ((m = atoi(s)) > 32) return 0;

	// calcula ip numerica a partir de octetos
	cnt = 1 << (32 - m); 
	net = (0xffffffff << (32 - m)) & 
		(o[0] << 24 | o[1] << 16 | o[2] << 8 | o[3]);

	// reservamos memoria para 
	*sbuf = p = (char *)x_malloc(cnt * 16);
	*hosts = (char **)x_malloc(cnt * sizeof(char *));

	// generamos todas las posibles IPs
	for (i = 0; i < cnt; i++)
	{
		(*hosts)[i] = p;
		p += sprintf(p, "%d.%d.%d.%d", 
			((net | i) & 0xff000000) >> 24, 
			((net | i) & 0x00ff0000) >> 16, 
			((net | i) & 0x0000ff00) >> 8, 
			((net | i) & 0x000000ff)) + 1;
	}

	return cnt;
}


// devuelve lista de puertos 
int calc_ports(char *str, u_short **ports)
{
	char *p, *tok, *idx;
	unsigned int from, to;
	int i, sz = 0;
	
	// reservamos memoria
	*ports = (u_short *)x_malloc(65536 * sizeof(u_short));

	// parseamos string separada por comas
	for (tok = str; (p = strtok(tok, ",")); tok = NULL)
	{
		// puerto origen valido ?
		if ((from = atoi(p)) && from < 65536) 
		{
			// hay hasta ?
			if ((idx = strchr(p, '-')))
			{
				// hasta valido ?
				if ((to = atoi(++idx)) > from && to < 65536)  
					for (i = from; i <= to; i++) 
						(*ports)[sz++] = i;
			}
			else (*ports)[sz++] = from;
		}
	}

	return sz;	
}


// datos a enviar para banner?
char *gen_banner_send(int port)
{
	char *r; 

	switch (port)
	{
		// http
		case 80: 
		case 3128:
		case 8000:
		case 8080:
		case 443:
		case 8443:

			// peticion en servicios web
			r = "HEAD / HTTP/1.0\r\n\r\n";

		break;

		// otros
		default:  
	
			// resto
			r = ".\n";
	}

	return r;
}


// calcula banner
char *gen_banner_recv(int port, const char *sbuf, int sz)
{
	static char banner[SZ_BANNER];
	const char *idx;

	switch (port)
	{
		// puertos http
		case 80: 
		case 3128:
		case 8080:

			// calculamos banner
			if (! (idx = strstr(sbuf, "Server:"))) 
				idx = sbuf;

			break;

		// resto
		default:  idx = sbuf;
	}

	// copiamos a banneR
	memset(banner, 0, SZ_BANNER);
	sz = sz - (idx - sbuf);
	sz = sz < SZ_BANNER ? sz : SZ_BANNER;
	memcpy(banner, idx, sz); 

	// limpiamos texto (pendiente)
	return clean_txt(banner, SZ_BANNER); 
}


// peticiones tcp
void scan()
{
	static char sbuf[SZ_SBUF];
	int i, j = 0, act = 0, sz;
	
	// mientras queden puertos por analizar
	while (j < sz_sl || act) 
	{
		// intentamos establecer conexiones
		for (i = act; i < MAX_CON && j < sz_sl; i++, j++)
		{
			// DEBUG 
			if (VERBOSE) printf("connecting %s:%d\n", 
					sl[j].host, sl[j].port);

			// iniciamos cronometro
			sl[j].start = crono();

			// lanzamos connects 
			switch (sl[j].status = init_conn( sl[j].addr, 
				sl[j].port, &(sl[j].socket)))
			{
				//  en ejecucion... 
				case X_PENDING: 

					// pool conexiones
					act++; 

				break;

				// a conectado
				case X_CONNECTED:

					// comenzamos lectura banner
					sl[j].status = X_PENDING_SEND;
					act++;

				break; 

				// rechazado, timeout, etc...
				case X_REFUSED:
				case X_TIMEOUT:

					// msg error
					if (VERBOSE) printf("%s:%-5d\t%s\t%4.0f ms\n", 
						sl[j].host, sl[j].port, 
						sl[j].status == X_TIMEOUT ? "timeout" : "refused", 
						crono() - sl[j].start);

					// liberamos recursos
					close_conn(sl[j].socket);

				break;

				// error?
				default: 

					// liberamos recursos
					close_conn(sl[j].socket);

					// msg error
					printf("%s:%-5d\t%s (%d)\t%4.0f ms\n", 
						sl[j].host, sl[j].port, "connect error", 
						sl[j].status, crono() - sl[j].start);
			}
		}

		// vemos pendientes...
		for (i = 0; i < j; i++)
		{
			// segun ultimo estado
			switch (sl[i].status) 
			{
				// conectando todavia?
				case X_PENDING: 

					// comprobamos...
					switch (sl[i].status = check_conn(sl[i].socket))
					{
						// conectando aun
						case X_PENDING:

							// timeout?
							if ((crono() - sl[i].start) > (TIMEOUT_CONN))
							{
								// marcamos como timeout
								sl[i].status = X_TIMEOUT;

								// liberamos recursos
								close_conn(sl[i].socket);
								act--;

								// msg error
								if (VERBOSE) printf("%s:%-5d\t%s\t%4.0f ms\n", 
									sl[i].host, sl[i].port, "timeout", 
									crono() - sl[i].start);
							}

						break;

						// ha conectado 
						case X_CONNECTED: 

							// pasamos a envio
							sl[i].status = X_PENDING_SEND;

						break;

						// timeout, refused, etc.
						case X_TIMEOUT:
						case X_REFUSED:
		
							// liberamos recursos
							close_conn(sl[i].socket);
							act--;

							// msg error
							if (VERBOSE) printf("%s:%-5d\t%s\t%4.0f ms\n", 
								sl[i].host, sl[i].port, 
								sl[i].status == X_TIMEOUT ? "timeout" : "refused", 
								crono() - sl[i].start);

						break; 

						// ha habido error?
						default:

							// liberamos recursos
							close_conn(sl[i].socket);
							act--;

							// msg error
							printf("%s:%-5d\t%s (%d)\t%4.0f ms\n", 
								sl[i].host, sl[i].port, "pending error", 
								sl[i].status, crono() - sl[i].start);

					}

				break; 
			
				// pendiente de envio peticion
				case X_PENDING_SEND: 

					// generamos peticion banner 
					x_strncpy(sbuf, gen_banner_send(sl[i].port), SZ_SBUF);
					sz = strlen(sbuf);

					// enviamos peticion 
					switch (sl[i].status = try_send(sl[i].socket, sbuf, sz))
					{
						// no preparado 
						case X_PENDING_SEND: 

							// timeout lectura?
							if ((crono() - sl[i].start) > (TIMEOUT_RW))
							{
								// marcamos como timeout
								sl[i].status = X_TIMEOUT;

								// liberamos recursos
								close_conn(sl[i].socket);
								act--;

								// suponemos que abierto
								printf("%s:%-5d\t%s\t%4.0f ms\t%s\n",
									sl[i].host, sl[i].port, "open", 
									crono() - sl[i].start, "(timeout!)");
							}

						break;

						// se ha enviado
						case  X_SEND: 

							// pasamos a pendiente recepcion
							sl[i].status = X_PENDING_RECV;

						break; 
		
						// se ha producido error
						default:

							// liberamos recursos
							close_conn(sl[i].socket);
							act--;

							// msg error
							printf("%s:%-5d\t%s\t%4.0f ms\t%s)\n", 
								sl[i].host, sl[i].port, "open", 
								crono() - sl[i].start, "(send err!)");
					}

				break;

				// pendiente recepcion banner
				case X_PENDING_RECV: 

					sz = SZ_SBUF; 

					// recibimos respuesta
					switch (sl[i].status = try_recv(sl[i].socket, sbuf, &sz))
					{
						// no preparado
						case X_PENDING_RECV: 

							// timeout lectura?
							if ((crono() - sl[i].start) > (TIMEOUT_RW))
							{
								// marcamos como timeout
								sl[i].status = X_TIMEOUT;

								// liberamos recursos
								close_conn(sl[i].socket);
								act--;

								// suponemos que abierto
								printf("%s:%-5d\t%s\t%4.0f ms\t%s\n",
									sl[i].host, sl[i].port, "open", 
									crono() - sl[i].start, "(timeout!)");
							}

						break; 

						// se ha leido
					 	case X_RECV:

							// marcamos como cerrada
							sl[i].status = X_CLOSED;
					
							// liberamos recursos
							close_conn(sl[i].socket); 
							act--;

							// imprimimos resultado
							printf("%s:%-5d\t%s\t%4.0f ms\t%s %02x %02x %02x %02x\n", 
								sl[i].host, sl[i].port, "open", 
								crono() - sl[i].start, 
								gen_banner_recv(sl[i].port, sbuf, sz),
								(unsigned char) sbuf[0], 
								(unsigned char) sbuf[1], 
								(unsigned char) sbuf[2], 
								(unsigned char) sbuf[3]
							);

						break; 

						// se ha producido error
						default:

							// liberamos recursos
							close_conn(sl[i].socket);
							act--;

							// msg error
							printf("%s:%-5d\t%s\t%4.0f ms\t%s\n", 
								sl[i].host, sl[i].port, "open", 
								crono() - sl[i].start, "(recv err!)");
					}
				break;
			}
		}

		// esperamos 
		usleep(WAIT);
	}
}


// funcion principal
int main(int argc, char **argv)
{
	struct hostent *host;
	char *sbuf, **hosts;
	int i, j, k, sz_hosts, sz_ports;
	u_short *ports;

#ifdef WIN32
	WSADATA wsaData;
	
	// init winsock
	if (WSAStartup(MAKEWORD(1, 1), &wsaData)) 
		x_abort("WSAStartup error");
#endif

	// desactivamos buffer salida
	setbuf(stdout, NULL);

	// usage
	if (argc < 2)
	{
		printf("usa: %s {network|filename|ip} [port,from-to]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	// hostnames en fichero ?
	if (!access(argv[1], F_OK))
	{
		// leemos
		sz_hosts = read_hosts(argv[1], &hosts, &sbuf);
	}

	// network ?
	else if (strchr(argv[1], '/')) 
	{
		// calculamos
		sz_hosts = calc_ips(argv[1], &hosts, &sbuf);
	}

	// ip unica ?
	else
	{	
		sbuf = (char *)x_malloc(SZ_HOST);
		hosts = (char **)x_malloc(sizeof(char *));
		x_strncpy(sbuf, argv[1], SZ_HOST);
		hosts[0] = sbuf; sz_hosts = 1;
	}

	// especificado puertos ?
	if (argc > 2)
	{
		// calculamos
		sz_ports = calc_ports(argv[2], &ports);
	}
	else 
	{
		ports = DEFAULT_PORTS;
		sz_ports = sizeof(DEFAULT_PORTS) / 	
			sizeof(u_short);
	}

	// reservamos memoria tabla scan 
	sz_sl = sz_hosts * sz_ports;
	sl = (t_sl *)x_malloc(sz_sl * sizeof(t_sl));

	// construimos tabla scan
	for (j = k = 0; j < sz_hosts; j++)
	{
		// resolucion host
		if (! (host = gethostbyname(hosts[j])))
		{
			// host no resuelve
			fprintf(stderr, "host no valido: %s\n", hosts[j]);
			exit(EXIT_FAILURE);
		}
		else
		{
			// matriz ip x puertos 
			for (i = 0; i < sz_ports; i++, k++)
			{
				x_strncpy(sl[k].host, hosts[j], SZ_HOST);
				sl[k].addr = *(struct in_addr *)host->h_addr;
				sl[k].port = ports[i]; 
				sl[k].status = X_PENDING;
			}
		}
	}

	// escaneamos
	scan();

	// borramos buffers
	free(sbuf);
	free(hosts); 
	free(sl);

	// puertos tambien?
	if (ports != DEFAULT_PORTS) free(ports);
	
#ifdef WIN32
	// cerramos winsock
	WSACleanup();		
#endif 

	return 0;
}
