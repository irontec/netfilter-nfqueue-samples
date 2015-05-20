#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/types.h>
#include <linux/netfilter.h>		
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/kernel.h>
#include <libmemcached/memcached.h>
#include <mysql/mysql.h>
/*
	Globales, para las pruebas de Memcache y Memcache
*/

memcached_server_st *servers = NULL;
memcached_st *memc;
memcached_return rc;
char *key= "keystring";
char *value= "keyvalue";

MYSQL *con;

/*
	::::	Funcion callback	:::
		================
	Es invocada cada vez que hay un paquete en la cola
*/
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	u_int32_t id;
        struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	unsigned char *nf_packet;
	char saddr[2048];
	int ret;
	char *valor_memcache;
	size_t len_memcache;
	char *key_memcache="autorizada";
	uint32_t flags;

	// Obtenemos las headers:
	ph = nfq_get_msg_packet_hdr(nfa);	
	// Y el ID de paquete, que hace falta para el veredicto final:
	id = ntohl(ph->packet_id);
     	// Obtenemos la IP origen del paquete:
	// - Primero hay que obtener el paquete en si:
	ret = nfq_get_payload(nfa, &nf_packet);
	if ((ret <= 0))
	{
		printf("Error, no hay paquete que recibir - wtf \n");
		return;
    	}

	struct iphdr *iph = ((struct iphdr *) nf_packet);
	inet_ntop(AF_INET, &(iph->saddr), saddr, sizeof(saddr));
//    	fprintf(stdout,"Recibido con origen%s\n",saddr);

	char consulta[2048];
	sprintf(consulta,"select SQL_NO_CACHE * from autorizada where ip like '%s'",saddr);
//	printf("QUERY: %s\n",consulta);
  	if (mysql_query(con, (const char*)consulta)) 
	{
		printf("Fail query ...\n");
	 	fprintf(stderr, "%s\n", mysql_error(con));
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
		
	 MYSQL_RES *result = mysql_store_result(con);
  	int num_rows = mysql_num_rows(result);
	mysql_free_result(result);

	if (num_rows >= 1)
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	else	return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);

}



int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("Obteniendo el handle de la libreria: ");
	h = nfq_open();
	if (!h) 
	{
		fprintf(stderr, "Ha fallado\n");
		exit(1);
	}
	else	printf(" OK !\n");

	printf("Haciendo unbind (por si existe alguno de AF_INET): ");
	if (nfq_unbind_pf(h, AF_INET) < 0) 
	{
		fprintf(stderr, "error nfq_unbind_pf()\n");
		exit(1);
	}
	else	printf(" OK!\n");

	printf("Vinculando nfnetlink_queue de tipo nf_queue handler para AF_INET:");
	if (nfq_bind_pf(h, AF_INET) < 0) 
	{
		fprintf(stderr, "error nfq_bind_pf()\n");
		exit(1);
	}
	else	printf(" OK!\n");

	printf("Creando la vinculacion de la funcion callback con Queue 0, socket receptor: ");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}
	else	printf(" OK !\n");

	printf("Definiendo que cantidad de paquete queremos recibir (no queremos todo para estas pruebas): ");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "FALLO el COPY_META mode\n");
		exit(1);
	}
	else	printf("OK\n");


	fd = nfq_fd(h);

	printf("Realizando conexión a memcache: ");
	memc= memcached_create(NULL);
	servers= memcached_server_list_append(servers, "localhost", 11211, &rc);
	rc= memcached_server_push(memc, servers);

	if (rc == MEMCACHED_SUCCESS)
		printf(" OK ! \n");
	else	{
			printf("error conectando a memcache: %s\n",memcached_strerror(memc, rc));
			exit(0);
		}

	printf("Realizando INIT de MySQL: ");
	con = mysql_init(NULL);
  	if (con == NULL)
  	{
      		printf(" FAIL\n");
      		exit(1);
  	}  
  	else	printf("OK\n");
	printf("Realizando Conexion a MYQSL: ");
	if (mysql_real_connect(con, "localhost", "root", "CHANGE_PASSWORD_FIXME", "nfqueue", 0, NULL, 0) == NULL) 
	  {
      		printf(" FAILED\n");
		exit(1);
	  }  
	else	printf(" OKI\n");


	printf("Todo Listo !\n Entrando en bucle principal de recepcion ..\n");
	while ((rv = recv(fd, buf, sizeof(buf), 0)))
	{
		// Si todo ha ido bien, gestionamos el paquete:
		if (rv>=0)
			nfq_handle_packet(h, buf, rv);
		
			// es posible que tengamos packet loss porque 
			// nuestro codigo es lento y se llena la queue:
		else if ( errno == ENOBUFS)
			{
				fflush(stdout);
				printf("!");
			}
			// O "simplemente", que algo haya ido mal:
		else {
				printf("ERROR \n");
				fflush(stdout);
				break;
			}
		
	}

	// Teoricamente, nunca llegaremos aqui, pero si llegamos

	// Habra que liberar bien y tal:
	printf("unbinding de queue 0\n");
	nfq_destroy_queue(qh);
	printf("cerrando library handle\n");
	nfq_close(h);

	exit(0);
}
