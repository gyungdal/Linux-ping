#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>    
#include <pwd.h>       
#include <sys/types.h>  
#include <ctype.h>
#include <sys/poll.h>
#include <time.h>

//전송할 패킷의 크기
#define PACKETSIZE 64

//전송할 패킷 구조체
struct packet{
	
	//ICMP 헤더
	struct icmphdr hdr;
	
	//패킷 전체 사이즈에서 icmp헤더를 제외한 공간, 메세지를 담을수 있다.	
    char msg[PACKETSIZE-sizeof(struct icmphdr)];
};

struct protoent *proto = NULL;
int cnt = 1, pid = -1, times = 10;

unsigned short checksum(void *b, int len);
int checkdigit(char*);

//문자열이 숫자인지 확인
int checkdigit(char* str){
	while(*str){
		char temp = *(str++);
		if(isdigit(temp) == 0)
			return 1;
	}
	return 0;
}

// 체크섬을 계산하는 함수
unsigned short checksum(void *b, int len){
    unsigned short *buf = b, result;
    unsigned int sum=0;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
	result = ~sum;
    return result;
}

void ping(char *address){
	clock_t start_point, end_point;
    const int ttl = 255;
    int i, sock, loop, success_stack = 0, loss_stack = 0;
    struct packet pckt;
    struct hostent *hname;
    struct sockaddr_in r_addr, addr_ping,*addr;
	struct pollfd pollsock;
    pid = getpid();
	
	//이름에 맞는 프로토콜을 반환
    proto = getprotobyname("ICMP");
    hname = gethostbyname(address);
	memset(&addr_ping, 0, sizeof(addr_ping));
    addr_ping.sin_family = hname->h_addrtype;
    addr_ping.sin_port = 0;
    addr_ping.sin_addr.s_addr = *(long*)hname->h_addr;

    addr = &addr_ping;
	sock = socket(PF_INET, SOCK_RAW, proto->p_proto);
    if(sock == -1){
        fprintf(stderr, "make socket fail\n");
		exit(EXIT_FAILURE);
    }
	
	//소켓의 옵션을 설정 이때 IP_TTL는 타입이 int형이기 때문에 담을 변수를 int로 선언해둔 val을 사용
	//time to live를 변경
    if (setsockopt(sock, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0){
        perror(strerror(errno));
		exit(EXIT_FAILURE);
    }
	
    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0){
        perror(strerror(errno));
		exit(EXIT_FAILURE);
    }
	
	//poll에 사용할 변수를 설정
	pollsock.fd = sock;
	pollsock.events = POLLIN | POLLERR | POLLPRI | POLLHUP | POLLNVAL; 
	pollsock.revents  = 0;
	
    for (loop=0;loop < times; loop++){
		//ECHO Request
        pckt.hdr.type = ICMP_ECHO;
        pckt.hdr.un.echo.id = pid;
		
		//메세지를 적당한 값으로 채운다
        for (i = 0; i < sizeof(pckt.msg)-1; i++)
            pckt.msg[i] = i+'A';
        pckt.msg[i] = 0;
		
        pckt.hdr.un.echo.sequence = cnt;
        pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));
        
        //전송
        if (sendto(sock, &pckt, sizeof(pckt), 0, (struct sockaddr*)addr, sizeof(*addr)) <= 0){
			perror(strerror(errno));
			exit(EXIT_FAILURE);
		}
		
		//송신 시간 기록
		start_point = clock();
        int len=sizeof(r_addr);

		while(1){
			//timeout 4초
			int state = poll((struct pollfd*)&pollsock, 1, 4000);
			if(state >= 0){
				if(state == 0){
					fprintf(stdout, "TIME OUT!!!\n");
				}
				break;
			}
		}
        //수신
        if (recvfrom(sock, &pckt, sizeof(pckt), 0, (struct sockaddr*)&r_addr, &len) > 0){
			//수신 시간 기록, 이 시간에서 송신할때의 시간을 빼서 총 걸린 시간 계산
            end_point = clock();
			success_stack++;
            fprintf(stdout, "[%d/%d] Success, icmp_seq : %d, Time : %f sec\n", loop+1, times, cnt++, ((double)(end_point - start_point)/CLOCKS_PER_SEC));
        }else{
			loss_stack++;
			fprintf(stdout, "[%d/%d] Fail\n", loop+1, times);
		}
            
		memset(&pckt, 0, sizeof(pckt));
    }
    
    //손실률(?)을 계산하고 전송한 패킷 수/성공한 횟수/손실률 출력
	double loss_value = (loss_stack != 0) ? (times / loss_stack) : 0.0;
	fprintf(stdout, "%d packets transmitted, %d received, %lf%% pocket loss\n", times, success_stack, loss_value);
}

//여기서는 주로 perror가 아닌 fprintf로 에러를 출력하는데 이것은 perror가 errno의 값을 해석해서 출력하므로 자꾸 Success 가 붙어서 제외했다.
//하지만 위에서 쓰는 함수들에는 거의 errno 의 내용을 출력하는 것이므로 대부분 perror을 사용했다.
int main(int argc, char *argv[]){ 
	if(argc < 2 || argc > 3){
		char error[100];
		sprintf(error, "<Caution : How to use?>\n%s <Address>\n%s <Address> <Time>\n", argv[0], argv[0]);
		fprintf(stderr, "%s", error);
		exit(EXIT_FAILURE);
	}
	if(argc == 3){
		if(checkdigit(argv[2])){
			fprintf(stderr, "Time is not number\n");
			exit(EXIT_FAILURE);
		}
		times = atoi(argv[2]);
	}
    if(getpwuid(getuid())->pw_uid != 0){
		fprintf(stderr, "Please try again in root user\n");
		exit(EXIT_FAILURE);
	}
	fprintf(stdout, "Ping send times : %d (Default : 10)\n", times);
	ping(argv[1]);
	exit(EXIT_SUCCESS);
}
