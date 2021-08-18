#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

// WireGuard ---> W2U --> udp2raw
int main(int argc, char* argv[])
{
    int ret, flags;
    int listener, sender, ep;
    int PORT_WG=51820, PORT_ENDP=29000, PORT_UR_BEGIN=29100, PORT_UR_SIZE=10;

    while((ret = getopt(argc, argv, "hf:l:t:s:")) != -1)
    {
        switch(ret)
        {
        case 'f':
            PORT_WG=atoi(optarg);
            break;
        case 'l':
            PORT_ENDP=atoi(optarg);
            break;
        case 't':
            PORT_UR_BEGIN=atoi(optarg);
            break;
        case 's':
            PORT_UR_SIZE=atoi(optarg);
            break;
        case 'h':
        default:
            fprintf(stderr, "Usage: %s -f WGPort -l ListenPort -t TargetPort -s TargetRange\n", argv[0]);
            exit(1);
        }
    }

    fprintf(stderr, "listening on %d, receiving from %d and sending to [%d,%d)\n", PORT_ENDP, PORT_WG, PORT_UR_BEGIN, PORT_UR_BEGIN+PORT_UR_SIZE);

    listener = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(PORT_ENDP);
    ret = bind(listener, (const struct sockaddr*)&saddr, sizeof(saddr));
    if (ret < 0) {
        perror("bind");
        exit(1);
    }

    sender = socket(AF_INET, SOCK_DGRAM, 0);

    // Set to non-blocking
    flags = fcntl(listener, F_GETFL, 0);
    if (flags < 0)
    {
        perror("fcntl");
        exit(1);
    }
    flags |= O_NONBLOCK;
    fcntl(listener, F_SETFL, flags);

    flags = fcntl(sender, F_GETFL, 0);
    if (flags < 0)
    {
        perror("fcntl");
        exit(1);
    }
    flags |= O_NONBLOCK;
    fcntl(sender, F_SETFL, flags);

    ep = epoll_create(1024);
    
    struct epoll_event ev1;
    ev1.events = EPOLLIN | EPOLLET;
    ev1.data.fd = listener;

    struct epoll_event ev2;
    ev2.events = EPOLLIN | EPOLLET;
    ev2.data.fd = sender;

    epoll_ctl(ep, EPOLL_CTL_ADD, listener, &ev1);
    epoll_ctl(ep, EPOLL_CTL_ADD, sender, &ev2);

    struct epoll_event events[1024];

    struct sockaddr_in* addrTargets = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in) * PORT_UR_SIZE);
    memset(addrTargets, 0, sizeof(struct sockaddr_in) * PORT_UR_SIZE);
    for(int i=0; i<PORT_UR_SIZE; i++) {
        addrTargets[i].sin_family = AF_INET;
        inet_pton(AF_INET, "127.0.0.1", &addrTargets[i].sin_addr);
        addrTargets[i].sin_port = htons(PORT_UR_BEGIN + i);
    }

    struct sockaddr_in addrWg;
    memset(&addrWg, 0, sizeof(addrWg));
    addrWg.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &addrWg.sin_addr);
    addrWg.sin_port = htons(PORT_WG);

    int rrOffset = 0;

    char buffer[4096];

    while(1)
    {
        int nfds = epoll_wait(ep, events, sizeof(events), -1);

        if (nfds < 0) {
            perror("epoll_wait");
            break;
        }

        for (int i=0;i<nfds; i++)
        {
            if (events[i].data.fd == listener) 
            {
                int nsize = recvfrom(listener, buffer, sizeof(buffer), 0, NULL, NULL);

                if (nsize < 0) {
                    perror("recvfrom");
                } else {
                    sendto(sender, buffer, nsize, 0, (const struct sockaddr*)(addrTargets + rrOffset), sizeof(struct sockaddr_in));
                    if (++rrOffset >= PORT_UR_SIZE) {
                        rrOffset = 0;
                    }
                }
            }
            else if (events[i].data.fd == sender)
            {
                int nsize = recvfrom(sender, buffer, sizeof(buffer), 0, NULL, NULL);

                if (nsize < 0) {
                    perror("recvfrom");
                } else {
                    sendto(listener, buffer, nsize, 0, (const struct sockaddr*)&addrWg, sizeof(struct sockaddr_in));
                }
            }
        }
    }
}
