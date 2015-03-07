#include <string.h> /*memcpy and memset*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <sys/stat.h>
#include <sys/types.h>

/*!
 \def pseudo_tcp
 *
 \brief The pseudo header structure use to compute the tcp checksum
 *
 \param saddr, source ip address
 \param daddr, dest ip address
 \param ptcl, protocol number (6 for tcp)
 \param mbz, flag (set to 0)
 \param tcpl, tcp + payload length (at least 20)
 *
 */
 struct pseudo_tcp
 {	// for little endian
 	unsigned saddr; 
 	unsigned daddr;
 #if defined(__LITTLE_ENDIAN_BITFIELD)
 	__u16	ptcl:8,
 	mbz:8;
 #else
 	__u16	mbz:8,
 	ptcl:8;
 #endif
 	unsigned short tcpl;
 };

 unsigned short tcp_cksum(unsigned short *pseudo_hdr, unsigned short *addr, int len);
 static int split_send(unsigned char *data, int tot_len, int position, int tot_hdrlen, int ip_hdr_len, int tcp_hdr_len);
 static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *dataw);

 static char *pid_file = NULL;
 static uint8_t ttl = 8;
 static int pre_hdr_len = 0;
 static char first_part[1500] __attribute__ ((aligned));
 static char second_part[1500] __attribute__ ((aligned));
 static char first_fake[1500] __attribute__ ((aligned));
 static char second_fake[72] __attribute__ ((aligned));
 static struct iphdr *ffip = (struct iphdr *)first_fake;
 static struct iphdr *fsip = (struct iphdr *)second_fake;
 static struct tcphdr *ftcp, *stcp, *fftcp, *fstcp;
 //avoid recv exit
 static char buf[65535] __attribute__ ((aligned));
 const char fake_baidu[15] = ": baidu.com\r\n\r\n"; 
 static int rawsocket = 0;
 static socklen_t tolen;
 static struct sockaddr_in dstaddr;
 static struct pseudo_tcp p_tcp;

 unsigned short tcp_cksum(unsigned short *pseudo_hdr, unsigned short *addr, int len)
 {
 	register int sum = 0;
 	u_short answer = 0;
 	register u_short *w = pseudo_hdr;
 	register int nleft = len;

    /*!
	* Our algorithm is simple, using a 32 bit accumulator (sum), we add
	* sequential 16 bit words to it, and at the end, fold back all the
	* carry bits from the top 16 bits into the lower 16 bits.
	*/

	sum = w[0] + w[1] + w[2] + w[3] + w[4] + w[5];
	w = addr;

	while (nleft > 1) {
		sum += htons(*addr++);
		nleft -= 2;
	}

	/*! mop up an odd byte, if necessary */
	if (nleft == 1) {
		answer = *(u_char *)addr << 8;
		sum += answer;
	}

	/*! add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);     /*! add hi 16 to low 16 */
	sum += (sum >> 16);                     /*! add carry */
	answer = htons(~sum);                          /*! truncate to 16 bits */
	return(answer);
}

static int split_send(unsigned char *data_n, int tot_len, int position, int tot_hdrlen, int ip_hdr_len, int tcp_hdr_len)
{
	unsigned long sseq;
	unsigned char *data = data_n;
	memcpy(second_part, data, tot_hdrlen);
    memcpy(second_part + tot_hdrlen, data + position, tot_len - position); //second tcp part
    memcpy(first_fake, data, tot_hdrlen);
    memcpy(second_fake, data, tot_hdrlen);
	memcpy(first_part, data, position); //ip header and first tcp part

    ffip -> ttl = ttl;
    fsip -> ttl = ttl;

    if (tot_hdrlen != pre_hdr_len) {
    	memset(first_fake + tot_hdrlen, 0, 16);
    	memcpy(second_fake + tot_hdrlen, fake_baidu, 15);
    	pre_hdr_len = tot_hdrlen;
    	ftcp = ((struct tcphdr *)(first_part + ip_hdr_len));
    	stcp = ((struct tcphdr *)(second_part + ip_hdr_len));
    	fftcp = ((struct tcphdr *)(first_fake + ip_hdr_len));
    	fstcp = ((struct tcphdr *)(second_fake + ip_hdr_len));
    }

    sseq = ntohl(stcp -> seq);
    
    p_tcp.saddr = htonl(ffip -> saddr);
    p_tcp.daddr = htonl(ffip -> daddr);

    p_tcp.tcpl 	= tot_len - position + tcp_hdr_len;
    stcp -> seq = htonl(sseq + position - tot_hdrlen);
    stcp -> check = 0x0;
    stcp -> check = (unsigned short)tcp_cksum((unsigned short *)&p_tcp, (unsigned short *)stcp, tcp_hdr_len + tot_len - position);
    //send to raw socket
    //sending order: 2->1f->2f->1
    dstaddr.sin_addr.s_addr = ffip -> daddr;
    if (-1 == sendto(rawsocket, second_part, tot_hdrlen + tot_len - position, 0, (struct sockaddr *)&dstaddr, tolen)) {
    	fprintf(stderr,"Error during sending second_part\n");
    	return -1;
    }

    p_tcp.tcpl 	= position - ip_hdr_len + 10;
    fftcp -> check = 0x0;
    fftcp -> check = (unsigned short)tcp_cksum((unsigned short *)&p_tcp, (unsigned short *)fftcp, tcp_hdr_len);

    if (-1 == sendto(rawsocket, first_fake, position + 10, 0, (struct sockaddr *)&dstaddr, tolen)) {
    	fprintf(stderr,"Error during sending first_fake\n");
    	return -1;
    }

    p_tcp.tcpl 	= tcp_hdr_len + 15;
    fstcp -> seq = htonl(sseq + position - tot_hdrlen + 10);
    fstcp -> check = 0x0;
    fstcp -> check = (unsigned short)tcp_cksum((unsigned short *)&p_tcp, (unsigned short *)fstcp, tcp_hdr_len + 15);

    if (-1 == sendto(rawsocket, second_fake, tot_hdrlen + 15, 0, (struct sockaddr *)&dstaddr, tolen)) {
    	fprintf(stderr,"Error during sending second_fake\n");
    	return -1;
    }

    p_tcp.tcpl 	= position - ip_hdr_len;
    ftcp -> check = 0x0;
    ftcp -> check = (unsigned short)tcp_cksum((unsigned short *)&p_tcp, (unsigned short *)ftcp, position - ip_hdr_len);

    if (-1 == sendto(rawsocket, first_part, position, 0, (struct sockaddr *)&dstaddr, tolen)) {
    	fprintf(stderr,"Error during sending first_part\n");
    	return -1;
    }
    return 0;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	struct nfq_data *nfa, void *dataw)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	int tot_len;
	int n;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph)
		id = ntohl(ph->packet_id);

	tot_len = nfq_get_payload(nfa, &data);

   //parse http request
   /*40+23 http://stackoverflow.com/questions/9233316/what-is-the-smallest-possible-http-and-https-data-request */
	if (tot_len > 63) {
		struct iphdr *iphdr;
		struct tcphdr *tcphdr;
		int tot_hdrlen;
		int tcp_hdr_len;
		int ip_hdr_len;

		iphdr = (struct iphdr*) data;
		ip_hdr_len = (iphdr -> ihl << 2);
		tcphdr = (struct tcphdr*) (data + ip_hdr_len);
		tcp_hdr_len = (tcphdr -> doff << 2);
		tot_hdrlen = ip_hdr_len + tcp_hdr_len;
		
		for (n = 16 + tot_hdrlen ; n < tot_len - 1; n++) {
			if (data[n] == 0x48) {
				n++;
				if (data[n] == 0x6F) {
					n++;
					if (data[n] == 0x73) {
						n++;
						if (data[n] == 0x74) {
							n++;
							if (data[n] == 0x3A) {
								n++;
								break;
							}
						}
					}
				}
			}
		}

		if (n < tot_len - 1) {
			if (!split_send(data, tot_len, n, tot_hdrlen, ip_hdr_len, tcp_hdr_len))
				return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		}
	}

	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	int one = 1;
	int option;
	uint16_t queue_num;
//some daemon initialization
	pid_t pid, sid;

	while ((option = getopt(argc, argv, "t:q:f:")) != -1) {
		switch (option) {
			case 't':
				if (atoi(optarg) < 256) {
					ttl = (uint8_t) (*optarg & 0xf);
				} else {
					printf("error, ttl must less than 256\n");
					exit(1);
				}
				break;
			case 'q':
				if (atoi(optarg) < 65536) {
					queue_num = (uint16_t) (*optarg & 0xf);
				} else {
					printf("error, ttl must less than 65536\n");
					exit(1);
				}
				break;
			case 'f':
				pid_file = strdup(optarg);
        		break;
			default:
				printf("error, only -t -q -f is allowed\n");
				exit(1);
		}
	}

	pid = fork();

	if (pid < 0) {
		exit(EXIT_FAILURE);
	}

	if (pid > 0) {
        FILE *file = fopen(pid_file, "w");
        if (file == NULL) {
            exit(EXIT_FAILURE);
        }

        fprintf(file, "%d", pid);
        fclose(file);
        exit(EXIT_SUCCESS);
	}

	umask(0);

	sid = setsid();
	if (sid < 0) {
		exit(EXIT_FAILURE);
	}

	if ((chdir("/")) < 0) {
		exit(EXIT_FAILURE);
	}

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
//the initialization ends here
	dstaddr.sin_family = AF_INET;
	dstaddr.sin_port = 80;
	tolen = sizeof(dstaddr);

	memset(first_part, 0x0, 1500);
	memset(second_part, 0x0, 1500);
	memset(first_fake, 0x0, 1500);
	memset(second_fake, 0x0, 72);
	//memcpy(second_fake + 40, fake_baidu, 15);

	memset(&p_tcp, 0x0, sizeof(struct pseudo_tcp));
	p_tcp.mbz = 0;
	p_tcp.ptcl = IPPROTO_TCP;

	//printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	//printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	//printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  queue_num, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	//printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

    //build a raw socket
	rawsocket = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (setsockopt(rawsocket,IPPROTO_IP,IP_HDRINCL,(char *)&one, sizeof(one)) < 0) {
		fprintf(stderr,"\nError creating raw socket.....\n");
		return -1;
	}

	while (rv = recv(fd, buf, sizeof(buf), 0)) {
		//printf("pkt received\n");
		if (rv > 0) {
		nfq_handle_packet(h, buf, rv);
		} else {
			continue;
		}
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
