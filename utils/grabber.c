
/***************************************************************
* simple tcp port scan (threads)
*
* features: 
*
*	- puede usar libcurl y libssh
*	- http(s), puede salvar la respuesta en ficheros
*	- ssh, prueba credenciales por defecto (root:root)
*
* linux: gcc tcp_scan.c -o tcp_scan -lpthread
* osx: gcc tcp_scan.c -o tcp_scan
* win32: gcc tcp_scan.c -o tcp_scan -lwsock32
* solaris: gcc tcp_scan.c -o tcp_scan -lsocket -lnsl
* 
* todas las opciones: gcc tcp_scan.c -Wall -o tcp_scan \
*			-I/opt/libssh2-1.4.3/include \
*			-L/opt/libssh2-1.4.3/lib \
*			-lssh2 -lpthread -lcurl \
*			-DSAVE_GET -DLIB_SSH -DLIB_CURL
*
****************************************************************/

#ifdef WIN32
#include <windows.h>
#include <winsock.h>
#else 
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef LIB_SSH2
#include <libssh2.h>
#endif 
#ifdef LIB_CURL
#include <curl/curl.h>
#endif


/*************************
 * parametrizacion
 *************************/

// configuracion
#ifdef SAVE_GET
#define OUT_DIR	"./out"		// directorio donde salvar ficheros
#define SZ_PATH 256		// tamanio maximo path
#endif
#define MAX_THREADS 50 		// concurrencia (ej. 25 threads)
#define INTERVAL 10 		// ms entre peticiones (ej. 10 ms)
#define TIMEOUT_RW 2000 	// timeout en r/w (ej. 6000 ms)
#define TIMEOUT_CONNECT 500 	// timeout en connect (ej. 1000 ms)
#define SZ_SBUF	1024		// tamanio de buffer de lectura
#define SZ_HOST 24		// longitud de hostname maxima
#ifdef WIN32
#define SZ_BANNER 40 		// long banner, mejor 40 para win32
#else
#define SZ_BANNER 80 		// long. banner
#endif
#define WH 16			// ancho hex


// puertos por defecto 
u_short DEFAULT_PORTS[] = 
{ 
	21, 22, 23, 25, 53, 79, 80, 88, 106, 110, 111, 135, 137, 138, 139, 143, 
	161, 162, 389, 443, 445, 465, 500, 512, 513, 514, 593, 636, 901, 993, 1080, 
	1241, 1433, 1434, 1723, 1812, 2000, 2049, 2601, 2605, 3306, 3128, 3389, 5060, 5353, 
	5432, 5666, 5800, 5900, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 
	6008, 6009, 6010, 6667, 8000, 8080, 8443, 8834, 10000, 10001, 10002, 
	10003, 10004, 10005, 10006, 10007, 10008, 10009, 10010 
};


/***************************
* tipos y variables globales
****************************/

#ifdef WIN32
typedef uint32_t socklen_t;
#endif 

// tipo scan line host:port
typedef struct 
{
	char host[SZ_HOST];
	struct in_addr addr;
	u_short port;

} t_sl;

// lista host:port 
t_sl *sl;
int sz_sl;

#ifdef SAVE_GET
FILE *fout;
#endif 

#ifdef LIB_SSH2
int libssh;
#endif

/*************************
 * threads
 *************************/

#define ARGS(x)	(*(t_args *)args).x
#ifdef WIN32
#define LOCK(x)	WaitForSingleObject(lck_##x, INFINITE)
#define UNLOCK(x) ReleaseMutex(lck_##x)
#else
#define LOCK(x) pthread_mutex_lock(&lck_##x)
#define UNLOCK(x) pthread_mutex_unlock(&lck_##x)
#endif

// bloqueos 
#if WIN32
HANDLE lck_print;
HANDLE lck_read;
HANDLE lck_path;
#else
pthread_mutex_t lck_print;
pthread_mutex_t lck_read;
pthread_mutex_t lck_path;
#endif

// argumentos thread
typedef struct { int thread_id; } t_args;


/*************************
 * funciones
 *************************/

// mensaje de error y salimos
void xabort(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}


// copia con final nulo
char *xstrncpy(char *s1, char *s2, int sz)
{
	char *r = NULL;

	if (sz) 
	{
		r = strncpy(s1, s2, sz);
		s1[sz - 1] = 0;
	}

	return r;
}


// asignacion de memoria, control errores
void *xmalloc(size_t sz)
{
	void *p;

	if ((p = malloc(sz)) == NULL)
		xabort("malloc error");

	return p;
}


// devuelve "ahora" en milisegundos 
double crono()
{
	struct timeval tim;

	gettimeofday(&tim, NULL);

	return ((tim.tv_sec * 1000000) + 
		tim.tv_usec) / 1000;
}


// quita retornos de carro y/o saltos
char *chomp(char *s)
{
	char *r = s;

	while (*r > 31 && *r < 127) r++;
	if (*r) *r = 0;
	
	return s;
}


// quita blancos a la izquierda
char *ltrim(char *s)
{
	while (*s == 32) s++;

	return s;
}


// quita caracteres no impr
char *do_printable(char *sbuf, size_t sz)
{
	size_t i; 
	char *s;

	// copiamos caracter si imprimible
	for (i = 0, s = sbuf; i < sz; i++, s++)
		*s = (*s < 32 || *s > 126 ? '.' : *s);

	// siempre termina en 0, ojo!!!!
	*s = 0;

	return sbuf;
}



// mostramos paquete en hexadecimal
void print_hex(const char *sbuf, size_t sz) 
{
	size_t i;  
	char s[WH + 1]; 

	// init string
	s[0] = s[WH] = 0;

	// imprime cada caracter en hex
	for (i = 0; i < sz; i++)
	{   
		if (i % WH == 0) printf("\t%s\n> ", s); 
		printf("%.2x ", 0x000000ff & sbuf[i]);
		s[i % WH] = sbuf[i] < 32 || sbuf[i] > 126 ?  '.' : sbuf[i];
	}

	// finalizamos salida
	if (i %= WH) for (s[i] = 0; i < WH; i++) printf("   ");

	printf("\t%s\n\n", s);
}


// intento establecimiento de conexion 
int tcp_open(struct in_addr addr, u_short port)
{
	int sock, r; 
	struct sockaddr_in sa; 
	struct timeval tv;
	fd_set set; 
	long arg;

	// creamos socket
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
		xabort("socket error");

#ifdef WIN32
	// sin bloqueo
	arg = 1; ioctlsocket(sock, FIONBIO, &arg);
#else
	arg = fcntl(sock, F_GETFL, NULL); 
	arg |= O_NONBLOCK; 
	fcntl(sock, F_SETFL, arg); 
#endif 

	// estructura server_addr
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr = addr;

	// intentamos conectar
	if ((r = connect(sock, (struct sockaddr *) &sa, sizeof(sa))) == -1) 
	{
#ifdef WIN32
		errno = WSAGetLastError();
#endif
		// error o en espera ?
		switch (errno) 
		{
#ifdef WIN32
			case WSAEWOULDBLOCK:
#else
			case 0:	// solaris ???
			case EINPROGRESS:
#endif
				tv.tv_sec = (TIMEOUT_CONNECT / 1000); 
				tv.tv_usec = (TIMEOUT_CONNECT % 1000) * 1000; 

				FD_ZERO(&set); 
				FD_SET(sock, &set); 

				// timeout de conexion y vemos respuesta
				if (select(sock + 1, NULL, &set, NULL, &tv) > 0)
				{ 
#ifdef WIN32
					r = !FD_ISSET(sock, &set);
#else 
					socklen_t lon = sizeof(int);
					getsockopt(sock, SOL_SOCKET, SO_ERROR, &r, &lon);
#endif
				} 

				// error o no conecta
				else  r = 1;

			break;

			default: xabort("connect error");
		}
	}

	return r ? 0 : sock;
}


// desconexion 
void tcp_close(int sock) 
{ 
	// sock valido ?
	if ( sock)
	{
#ifdef WIN32
		closesocket(sock);
#else
		shutdown(sock, SHUT_RDWR);
		close(sock); 
	}
#endif
}


// respuesta
int tcp_recv(int sock, char *sbuf, int sbuf_sz)
{
	int sz;
	struct timeval tv;
	fd_set set;
	
	FD_ZERO(&set);
	FD_SET(sock, &set);

	tv.tv_sec = (TIMEOUT_RW / 1000);
	tv.tv_usec = (TIMEOUT_RW % 1000) * 1000;

	// leemos de socket si hay datos
	switch (select(sock + 1, &set, NULL, NULL, &tv))
	{
		case 0: 
		
			// timeout
			sz = 0;
			break; 

		case -1: 

			// error 
			xabort("select error"); 
			break;

		default:
			// preparado
			if ((sz = recv(sock, sbuf, sbuf_sz, 0)) == -1) 
				xabort("recv error");
	}

	return sz;
}


// peticion
int tcp_send(int sock, const char *sbuf)
{
	int sz; 
	struct timeval tv;
	fd_set set;

	FD_ZERO(&set);
	FD_SET(sock, &set);

	tv.tv_sec = (TIMEOUT_RW / 1000);
	tv.tv_usec = (TIMEOUT_RW % 1000) * 1000;

	// enviamos datos cuando este preparado
	switch (select(sock + 1, NULL, &set, NULL, &tv)) 
	{
		case 0: 

			// timeout
			sz = 0; 
			break; 

		case -1: 

			// error
			xabort("select error"); 
			break;

		default:

			// preparado 
			if ((sz = send(sock, sbuf, strlen(sbuf), 0)) == -1)
				xabort("send error");
	}

	return sz;
}


// leemos hostnames de fichero de texto
int read_hosts(const char *fname, char **hosts[], char **sbuf)
{
	int sz = 0;
	char *p, *s;
	struct stat st;
	FILE *F;

	// existe el fichero ?
	if ((stat(fname, &st) != -1) && (F = fopen(fname, "r")))
	{
		// tamanio fichero?
		if (st.st_size) 
		{
			// reservamos memoria
			*sbuf = p = (char *)xmalloc(st.st_size);

			// leemos contenido
			fread(*sbuf, 1, st.st_size, F);

			// contamos el numero de hosts
			while (*p) if (*p++ == '\n') sz++; 
			if (sz) sz++;

			// reservamos memoria
			*hosts = (char **)xmalloc(sz * sizeof(char *));

			// contamos lineas y saltamos comments o vacios
			for (p = *sbuf, sz = 0; (s = strtok(p, "\n")); p = NULL)
				if (*s && *s != '#') (*hosts)[sz++] = s;
		}

		// cerramos fichero
		fclose(F);
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
	*sbuf = p = (char *)xmalloc(cnt * 16);
	*hosts = (char **)xmalloc(cnt * sizeof(char *));

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
int get_ports(char *str, u_short **ports)
{
	char *p, *tok, *idx;
	unsigned int from, to;
	int i, sz = 0;
	
	
	// reservamos memoria
	*ports = (u_short *)xmalloc(65536 * sizeof(u_short));

	// parseamos string, separada por comas
	for (tok = str; (p = strtok(tok, ",")); tok = NULL)
	{
		// puerto origen valido ?
		if ((from = atoi(p))  && from < 65536) 
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


#ifdef LIB_CURL
// puntero auxiliar 
char *curl_ptr; 

// funcion auxiliar, tratamiento datos curl
static size_t curl_write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
	// obtenemos banner 
	if (!strncmp(ptr, "Server:", 7)) strncpy(curl_ptr, ptr, SZ_BANNER); 

#ifdef SAVE_GET
	// guardamos fichero
	return fwrite(ptr, size, nmemb, (FILE *)stream);
#else
	return 0;
#endif 
}
#endif


#ifdef SAVE_GET
// contruimos path a partir de ip:port
char *create_path(char *host, int port)
{
	static char path[SZ_PATH]; 
	char *idx;

	// construimos nombre fichero
	sprintf(path, OUT_DIR"/%s:%d", host, port);
	idx = path + strlen(OUT_DIR) + 1; 
	
	// http://192.168.0.1:80 -> out/192/168/0/1:80
	while (*idx) 
	{ 
		if (*idx == '.') 
		{
			*idx = 0; 
			mkdir(path, 0);
			*idx = '/'; 
		}

		idx++; 
	}

	return path; 
}
#endif


#define	HEADER(h, sbuf)	((idx = strstr(sbuf, h)) ? idx + strlen(h) : "")

// peticiones tcp
#ifdef WIN32
static DWORD WINAPI run(void* args)
#else
void *run(void *args)
#endif
{
	int s, i, th_id, sz;
	char sbuf[SZ_SBUF];
	double start, stop;
	char banner[SZ_BANNER];
	char *status[] = { "open", "close" };
#ifdef SAVE_GET
	int first, code;
	char path[SZ_PATH], *idx;
	FILE *F;
#endif
#ifdef LIB_SSH2
	LIBSSH2_SESSION *ssh;
#endif
#ifdef LIB_CURL
	CURL *curl;
#endif

	// argumentos (in)
	th_id = ARGS(thread_id);
 
	// fuzz de parametros
	for (i = th_id; i < sz_sl; i += MAX_THREADS)
	{
		// iniciamos cronometro
		start = crono();

		// inicializamos cadenas
		*sbuf = *banner = '\0';

		// conectamos
		if ((s = tcp_open(sl[i].addr, sl[i].port)))
		{
			switch (sl[i].port)
			{
				// HTTP_PROXY
				case 3128:

					// enviamos peticion en servicios web
					tcp_send(s, "GET http://www.google.com HTTP/1.0\r\n\r\n"); 

					// leemos respuesta 
					sz = tcp_recv(s, banner, SZ_BANNER - 1);
					
					break;

				// HTTP
				case 80:
				case 8080:
#ifdef SAVE_GET
					// enviamos peticion en servicios web
					tcp_send(s, "GET / HTTP/1.0\r\n"
							"Host: 192.168.1.1\r\n"
							"Authorization: Basic YWRtaW46MTIzNA==\r\n"
							"\r\n"); 
				
					// creamos path
					LOCK(path); 
					strncpy(path, create_path(sl[i].host, sl[i].port), SZ_PATH); 
					UNLOCK(path);

					// abrimos fichero
					if ((F = fopen(path, "rw+")) == 0) xabort("fopen error");
	
					first = 1; code = 0;

					// leemos respuesta 
					while ((sz = tcp_recv(s, sbuf, SZ_SBUF)))
					{ 
						// y salvamos a fichero
						fwrite(sbuf, 1, sz, F);

						// solo calculamos banner 1er paquete
						if (first) 
						{
							// calculamos banner (1 vez)
							code = atoi(HEADER("HTTP/1.", sbuf) + 2);
							xstrncpy(banner, ltrim(chomp(HEADER("Server:", 
								sbuf))), SZ_BANNER);

							// salvamos resultados
							LOCK(print); 
							fprintf(fout, "%s;%d;%d;%s\n", sl[i].host, sl[i].port, code, banner); 
							UNLOCK(print);

							first = 0;
						}
					}

					// apanio temporal
					sz = strlen(banner);
	
					// cerramos fichero
					fclose(F);
#else
					// enviamos peticion en servicios web
					tcp_send(s, "HEAD / HTTP/1.0\r\n\r\n"); 

					// leemos respuesta 
					sz = tcp_recv(s, banner, SZ_BANNER - 1);
#endif
					break;
#ifdef LIB_CURL
				// HTTPS
				case 443:

					// creamos una sesion curl
					if ((curl = curl_easy_init()) != 0)
					{
						// indicamos url conexion
						curl_easy_setopt(curl, CURLOPT_URL, sl[i].host);

						// opciones ssl
						curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
						curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

						// otras opciones
						curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
						curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_RW);

						// construimos nombre fichero
						LOCK(path);
						strncpy(path, create_path(sl[i].host, sl[i].port), SZ_PATH);
						UNLOCK(path);

						// abrimos fichero
						if ((F = fopen(path, "w+")) == NULL) xabort("Xfopen error");

						// callback para gestionar datos recibidos
						curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_data);
						curl_easy_setopt(curl, CURLOPT_WRITEHEADER, F);
						curl_easy_setopt(curl, CURLOPT_WRITEDATA, F);

						// apanio para obtener el banner
						curl_ptr = banner;

						// lanzamos peticion
						//if (curl_easy_perform(curl) != CURLE_OK) xabort("curl error");
						curl_easy_perform(curl);
					}

					// apanio 
					sz = strlen(banner);

					// liberamos recursos
					curl_easy_cleanup(curl);

					// cerramos fichero
					fclose(F);
					
					break;
#endif
#ifdef LIB_SSH2
				// SSH 
				case 22:

					// creamos una sesion ssh
					if ((ssh = libssh2_session_init()))
					{
						// primero timeout
						libssh2_session_set_timeout(ssh, TIMEOUT_RW);

						// ssh handshake ?
						if (!(libssh2_session_handshake(ssh, s)))
						{
							// banner e intentamos autentiacion con root:root
							if (libssh2_userauth_password(ssh, "root", "root")) 
								sprintf(banner, libssh2_session_banner_get(ssh));
							
							// conectados y autenticados !!!
							else
							{
								sprintf(banner, "%s\tAUTH! (root:root)", 
									libssh2_session_banner_get(ssh));
							}

							// apanio temporal
							sz = strlen(banner);
						}
					}

					// desconectamos
					libssh2_session_disconnect(ssh, "shutdown");

					// cerramos sesion
    					libssh2_session_free(ssh);

					break; 
#endif
				default: 

					// enviamos peticion generica
					tcp_send(s, "\n"); 

					// leemos respuesta
					sz = tcp_recv(s, banner, SZ_BANNER - 1);
			}

			// paramos cronometro
			stop = crono();

			if (sz) 
			{
				// solo chars impr
				memcpy(sbuf, banner, sz);
				do_printable(banner, sz);

				// imprimimos resultados
				LOCK(print); 
				printf("%s:%d\t%s\t%.0f ms\t%s\n", sl[i].host, sl[i].port, 
					status[s == 0], stop - start, banner); 
				print_hex(sbuf, sz);
				UNLOCK(print);
			}
		}

		// cerramos socket
		tcp_close(s); 

		// esperamos
		usleep(INTERVAL);
	}

	return 0;
}


// funcion principal
int main(int argc, char **argv)
{
	t_args args[MAX_THREADS];
	struct hostent *host;
	char *sbuf, **hosts;
	int th, i, j, k, sz_hosts, sz_ports;
	u_short *ports;
#ifdef WIN32
	WSADATA wsaData;
	HANDLE threads[MAX_THREADS];
	DWORD threads_id[MAX_THREADS];
	
	// init winsock
	if (WSAStartup(MAKEWORD(1, 1), &wsaData)) 
		xabort("WSAStartup error");
	
	// init mutexs
	lck_print = CreateMutex(NULL, FALSE, NULL);
	lck_read = CreateMutex(NULL, FALSE, NULL);
#else 
	pthread_t threads[MAX_THREADS];
#endif

	// desactivamos buffer salida
	setbuf(stdout, NULL);

	// usage
	if (argc < 2)
	{
		printf("usage: %s {network|filename|ip} [port,from-to]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	// --------------------
	// primer parametro ...
	// --------------------

	// hostnames en fichero ?
	if (!access(argv[1], F_OK))
		sz_hosts = read_hosts(argv[1], &hosts, &sbuf);

	// network ?
	else if (strchr(argv[1], '/')) 
		sz_hosts = calc_ips(argv[1], &hosts, &sbuf);

	// ip unica ?
	else
	{	
		sbuf = (char *)xmalloc(SZ_HOST);
		hosts = (char **)xmalloc(sizeof(char *));
		xstrncpy(sbuf, argv[1], SZ_HOST);
		hosts[0] = sbuf; sz_hosts = 1;
	}

	// especificado puertos ?
	if (argc > 2)
		sz_ports = get_ports(argv[2], &ports);

	else 
	{
		ports = DEFAULT_PORTS;
		sz_ports = sizeof(DEFAULT_PORTS) / 	
			sizeof(u_short);
	}

	// tamanio tabla scan ?
	sz_sl = sz_hosts * sz_ports;

	// reservamos memoria tabla scan 
	sl = (t_sl *)xmalloc(sz_sl * sizeof(t_sl));

	// construimos tabla scan
	for (j = 0, k = 0; j < sz_hosts; j++)
	{
		// resolucion host
		if ((host = gethostbyname(hosts[j])) == 0)
			fprintf(stderr, "host no valido: %s\n", hosts[j]);

		else
			// matriz ip x puertos 
			for (i = 0; i < sz_ports; i++, k++)
			{
				xstrncpy(sl[k].host, hosts[j], SZ_HOST);
				sl[k].addr = *(struct in_addr *)host->h_addr;
				sl[k].port = ports[i]; 
			}
	}
#ifdef SAVE_GET
	// creamos directorio de salida
	mkdir(OUT_DIR, 0);

	// creamos fichero indice
	if (!(fout = fopen(OUT_DIR "/index.txt", "a+")))
		xabort("fopen error");
#endif
#ifdef LIB_SSH2
	// inicializamos libreria
	if (libssh2_init(0)) xabort("libssh2_init error");
#endif 
#ifdef LIB_CURL
	curl_global_init(CURL_GLOBAL_DEFAULT);
#endif

	// lanzamos todas las tareas
	for (th = 0; th < MAX_THREADS; th++)
	{
		// identificador tarea
		args[th].thread_id = th;
#ifdef WIN32
		// ejecuta thread
		if (!(threads[th] = CreateThread(NULL, 0, run, 
			(void*)&args[th], 0, &threads_id[th])))
				xabort("CreateThread error");
#else 
		// ejecuta thread
		if (pthread_create(&threads[th], NULL, run, &args[th]))
			xabort("pthread_create error");
#endif
	}

	// espera a que terminen todas las tareas
	for (th = 0; th < MAX_THREADS; th++)
	{
#ifdef WIN32
		if (WaitForSingleObject(threads[th], INFINITE))	
			xabort("WaitForSingleObject error");

		CloseHandle(threads[th]);
#else
		if (pthread_join(threads[th], NULL))
			xabort("pthread_join error");
#endif
	}
#ifdef SAVE_GET
	// cerramos fichero
	fclose(fout);
#endif 
	// borramos buffers
	free(hosts); free(sbuf);
	if (ports != DEFAULT_PORTS) free(ports);
	free(sl);
#ifdef WIN32
	// cerramos mutexs
	CloseHandle(lck_print);
	CloseHandle(lck_read);

	// cerramos winsock
	WSACleanup();		
#endif 
#ifdef LIB_SSH2
	// liberamos libreria
	libssh2_exit();
#endif 
#ifdef LIB_CURL
	// liberamos libreria
	curl_global_cleanup();
#endif
	return 0;
}
