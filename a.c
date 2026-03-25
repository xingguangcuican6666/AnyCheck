#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <arpa/inet.h>

void process_msg(struct nlmsghdr *nh) {
    struct ifinfomsg *ifm = (struct ifinfomsg *)NLMSG_DATA(nh);
    struct rtattr *rta = IFLA_RTA(ifm);
    int rtl = IFLA_PAYLOAD(nh);

    char name[IFNAMSIZ] = {0};
    unsigned char mac[6] = {0};
    int has_mac = 0;

    for (; RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
        if (rta->rta_type == IFLA_IFNAME) {
            strncpy(name, (char *)RTA_DATA(rta), IFNAMSIZ - 1);
        }
        if (rta->rta_type == IFLA_ADDRESS) {
            memcpy(mac, RTA_DATA(rta), 6);
            has_mac = 1;
        }
    }

    if (has_mac && strcmp(name, "lo") != 0) {
        printf("[+] 接口: %s | MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
                name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        
        // Android 11+ 风险判定逻辑
        int is_all_zero = 1;
        for(int i=0; i<6; i++) if(mac[i] != 0) is_all_zero = 0;
        
        if (!is_all_zero) {
            printf("  🚨 风险：在 Android 11+ 上发现非零 MAC 地址！\n");
        }
    }
}

int main() {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct {
        struct nlmsghdr nh;
        struct ifinfomsg ifm;
    } req;

    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nh.nlmsg_type = RTM_GETLINK;
    req.ifm.ifi_family = AF_PACKET;

    send(sock, &req, req.nh.nlmsg_len, 0);

    char buf[8192];
    int len = recv(sock, buf, sizeof(buf), 0);
    struct nlmsghdr *nh = (struct nlmsghdr *)buf;

    while (NLMSG_OK(nh, len)) {
        if (nh->nlmsg_type == NLMSG_DONE) break;
        process_msg(nh);
        nh = NLMSG_NEXT(nh, len);
    }

    close(sock);
    return 0;
}

