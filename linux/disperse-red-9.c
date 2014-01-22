#include <net/ip.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>

struct packet_type net_if_proto;

void process_packet(struct sk_buff *skb)
{
    struct ethhdr *eth;
    struct iphdr  *iph;
    struct tcphdr *tph;
    int    src_port,dest_port;

    eth = eth_hdr(skb);
    iph = ip_hdr(skb);

    if(iph->protocol == 6)   // tcp
    {
        tph = (struct tcphdr*) (((char*) iph) + iph->ihl * 4);
        src_port  = htons(tph->source);
        dest_port = htons(tph->dest);

// Nmap tests ECN by sending a SYN packet which also has the ECN CWR and ECE congestion control flags set. 
// For an unrelated (to ECN) test, the urgent field value of 0xF7F5 is used even though the urgent flag 
// is not set. The acknowledgment number is zero, sequence number is random, window size field is three,
//  and the reserved bit which immediately precedes the CWR bit is set. TCP options are WScale (10), NOP,
//  MSS (1460), SACK permitted, NOP, NOP. 

        if(tph->syn == 1 && tph->ece == 1 && tph->cwr == 1 && tph->window == htons(3))
        {
            printk("[+] NMAP Explicit Congestion Notification probe from %pI4!\n",&iph->saddr);
        }

// T2 sends a TCP null (no flags set) packet with the IP DF bit set and a window 
//     field of 128 to an open port.

        if(tph->syn == 0 && tph->ack == 0 && tph->fin == 0 && tph->psh == 0 
            && tph->urg == 0 && tph->rst == 0 && iph->frag_off == ntohs(IP_DF) 
                && tph->window == htons(128))
        {
            printk("[+] NMAP OS detection probe (T2) from %pI4!\n",&iph->saddr);
        }

// T3 sends a TCP packet with the SYN, FIN, URG, and PSH flags set and a window 
//      field of 256 to an open port. The IP DF bit is not set.

        if(tph->syn == 1 && tph->fin == 1 && tph->psh == 1 && tph->urg == 1 
            && tph->window == htons(256) && iph->frag_off != ntohs(IP_DF))
        {
            printk("[+] NMAP OS detection probe (T3) from %pI4!\n",&iph->saddr);
        }

// T4 sends a TCP ACK packet with IP DF and a window field of 1024 to an open port.

        if(tph->ack == 1 && iph->frag_off == ntohs(IP_DF) && tph->window == htons(1024))
        {
            printk("[+] NMAP OS detection probe (T4) from %pI4!\n",&iph->saddr);
        }

// T5 sends a TCP SYN packet without IP DF and a window field of 31337 to a closed port.

        if(tph->syn == 1 && iph->frag_off != ntohs(IP_DF) && tph->window == htons(31337))
        {
            printk("[+] NMAP OS detection probe (T5) from %pI4!\n",&iph->saddr);
        }

// T6 sends a TCP ACK packet with IP DF and a window field of 32768 to a closed port.

        if(tph->ack == 1 && iph->frag_off == ntohs(IP_DF) && tph->window == htons(32768))
        {
            printk("[+] NMAP OS detection probe (T6) from %pI4!\n",&iph->saddr);            
        }

// T7 sends a TCP packet with the FIN, PSH, and URG flags set and a window field of 
//      65535 to a closed port. The IP DF bit is not set.

        if(tph->fin == 1 && tph->psh == 1 && tph->urg == 1 && iph->frag_off != ntohs(IP_DF) 
            && tph->window == htons(65535))
        {
            printk("[+] NMAP OS detection probe (T7) from %pI4!\n",&iph->saddr);
        }
 
// Generic scan detection. 
        if((tph->syn == 1 && dest_port == 21) || (tph->syn == 1 && dest_port == 22) ||
           (tph->syn == 1 && dest_port == 80) || (tph->syn == 1 && dest_port == 443))
        {
            printk("[+] Generic probe to port %d from %pI4!\n",dest_port,&iph->saddr);
        }
    }
}

int packet_func(struct sk_buff *skb, struct net_device *dev, 
                      struct packet_type *pt, struct net_device *deev) 
{
    if (skb->pkt_type == PACKET_HOST)
    {
        process_packet(skb); 
        kfree_skb(skb);
    }
    return 0;
}

int init_module(void)  
{
    printk("Module loaded.. Registering handler..\n");
    net_if_proto.dev =  NULL;
    net_if_proto.type = htons(ETH_P_ALL); 
    net_if_proto.func = packet_func;
    dev_add_pack(&net_if_proto);
    printk("Handler registered.. Starting capture..\n");
    return 0;
}

void cleanup_module(void) 
{
    printk("Unregistering handler..\n");
    dev_remove_pack(&net_if_proto); 
    printk("protocol unregistered.. terminating.\n");
}

MODULE_LICENSE("GPL");
