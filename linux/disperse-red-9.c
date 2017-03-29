#include <net/ip.h>
#include <net/tcp.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>

#include "disperse-red-9.h"

struct packet_type net_if_proto;
struct statman *statman; 

void process_packet(struct sk_buff *skb)
{
    struct ethhdr        *eth;
    struct iphdr         *iph;
    struct tcphdr        *tph;
    int src_port,dest_port;
    eth = eth_hdr(skb);
    iph = ip_hdr(skb);

    if(iph->protocol == 6)   // tcp
    {
        tph = (struct tcphdr*) (((char*) iph) + iph->ihl * 4);
        src_port  = htons(tph->source);
        dest_port = htons(tph->dest);

// SYN scan (-sS)
// aka 'half open' scan - "SYN scan is the default and most popular scan option"
// (requires the user to be running as root)
// 
// SYN scans can be detected by:
// 1)  Small window size (either 1024, 2048, 3072, 4096 bytes)
// 2)  No timestamp
// 3)  MSS 1460
// 4)  MSS is the only TCP option set

      if((tph->syn == 1 && tph->ack == 0) && (tph->window == htons(1024) || tph->window == htons(2048) 
                                            ||tph->window == htons(3072) || tph->window == htons(4096)))
      {
          printk("[+] NMAP SYN Scan from %pI4!\n",&iph->saddr);
          statman->syn_scan++; 
      }

// Xmas scan (-sX)
// Sets the FIN, PSH, and URG flags, lighting the packet up like a Christmas tree.

       if(tph->fin == 1 && tph->psh == 1 && tph->urg == 1)
       {
           printk("[+] NMAP XMAS Tree Scan from %pI4!\n",&iph->saddr);
           statman->xmas_scan++; 
       }

// Null scan (-sN) 
// Does not set any bits (TCP flag header is 0)

       if(tph->syn == 0 && tph->ack == 0 && tph->rst == 0 && tph->fin == 0 && tph->psh == 0 && tph->urg == 0)
       {
           printk("[+] NMAP NULL Scan from %pI4!\n",&iph->saddr);
           statman->null_scan++; 
       }

// FIN scan (-sF)
// Sets just the TCP FIN bit.

       if(tph->syn == 0 && tph->ack == 0 && tph->rst == 0 && tph->fin == 1 && tph->psh == 0 && tph->urg == 0)
       {
           printk("[+] NMAP FIN Scan from %pI4!\n",&iph->saddr);
           statman->fin_scan++; 
       }

// Nmap tests ECN by sending a SYN packet which also has the ECN CWR and ECE congestion control flags set. 
// For an unrelated (to ECN) test, the urgent field value of 0xF7F5 is used even though the urgent flag 
// is not set. The acknowledgment number is zero, sequence number is random, window size field is three,
//  and the reserved bit which immediately precedes the CWR bit is set. TCP options are WScale (10), NOP,
//  MSS (1460), SACK permitted, NOP, NOP. 

        if(tph->syn == 1 && tph->ece == 1 && tph->cwr == 1 && tph->window == htons(3))
        {
            printk("[+] NMAP Explicit Congestion Notification probe from %pI4!\n",&iph->saddr);
            statman->ecn_scan++; 
        }

// T2 sends a TCP null (no flags set) packet with the IP DF bit set and a window 
//     field of 128 to an open port.

        if(tph->syn == 0 && tph->ack == 0 && tph->fin == 0 && tph->psh == 0 
            && tph->urg == 0 && tph->rst == 0 && iph->frag_off == ntohs(IP_DF) 
                && tph->window == htons(128))
        {
            printk("[+] NMAP OS detection probe (T2) from %pI4!\n",&iph->saddr);
            statman->t2_scan++;
        }

// T3 sends a TCP packet with the SYN, FIN, URG, and PSH flags set and a window 
//      field of 256 to an open port. The IP DF bit is not set.

        if(tph->syn == 1 && tph->fin == 1 && tph->psh == 1 && tph->urg == 1 
            && tph->window == htons(256) && iph->frag_off != ntohs(IP_DF))
        {
            printk("[+] NMAP OS detection probe (T3) from %pI4!\n",&iph->saddr);
            statman->t3_scan++;
        }

// T4 sends a TCP ACK packet with IP DF and a window field of 1024 to an open port.

        if(tph->ack == 1 && iph->frag_off == ntohs(IP_DF) && tph->window == htons(1024))
        {
            printk("[+] NMAP OS detection probe (T4) from %pI4!\n",&iph->saddr);
            statman->t4_scan++;
        }

// T5 sends a TCP SYN packet without IP DF and a window field of 31337 to a closed port.

        if(tph->syn == 1 && iph->frag_off != ntohs(IP_DF) && tph->window == htons(31337))
        {
            printk("[+] NMAP OS detection probe (T5) from %pI4!\n",&iph->saddr);
            statman->t5_scan++;
        }

// T6 sends a TCP ACK packet with IP DF and a window field of 32768 to a closed port.

        if(tph->syn == 0 && tph->ack == 1 && iph->frag_off == ntohs(IP_DF) 
            && tph->window == htons(32768))
        {
            printk("[+] NMAP OS detection probe (T6) from %pI4!\n",&iph->saddr);
            statman->t6_scan++;   
        }

// T7 sends a TCP packet with the FIN, PSH, and URG flags set and a window field of 
//      65535 to a closed port. The IP DF bit is not set.

        if(tph->fin == 1 && tph->psh == 1 && tph->urg == 1 && iph->frag_off != ntohs(IP_DF) 
            && tph->window == htons(65535))
        {
            printk("[+] NMAP OS detection probe (T7) from %pI4!\n",&iph->saddr);
            statman->t7_scan++;   
        }
 
// Generic connect() scan detection. 
        if((tph->syn == 1 && dest_port == 20) || (tph->syn == 1 && dest_port == 21)||
           (tph->syn == 1 && dest_port == 23) || (tph->syn == 1 && dest_port == 138))
        {
            printk("[+] Generic probe to port %d from %pI4!\n",dest_port,&iph->saddr);
            statman->generic++;   
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

static int dr9_stats_show(struct seq_file *m, void *v)
{
    seq_printf(m, "NMAP Xmas Tree: %d\n"
                  "NMAP      Null: %d\n"
                  "NMAP       SYN: %d\n" 
                  "NMAP       FIN: %d\n" 
                  "NMAP       ECN: %d\n" 
                  "NMAP        T2: %d\n" 
                  "NMAP        T3: %d\n" 
                  "NMAP        T4: %d\n" 
                  "NMAP        T5: %d\n" 
                  "NMAP        T6: %d\n" 
                  "NMAP        T7: %d\n" 
                  "Generic Probes: %d\n" 
                    ,statman->xmas_scan
                    ,statman->null_scan
                     ,statman->syn_scan
                     ,statman->fin_scan
                     ,statman->ecn_scan
                      ,statman->t2_scan
                      ,statman->t3_scan
                      ,statman->t4_scan
                      ,statman->t5_scan
                      ,statman->t6_scan
                      ,statman->t7_scan
                      ,statman->generic);
    // I spent a long time playing with 
    // the formatting to make it pretty. 
    return 0;
}

static int dr9_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, dr9_stats_show, NULL);
}

static const struct file_operations dr9_fops = {
    .owner        = THIS_MODULE,                 
    .open         = dr9_proc_open,      
    .read         = seq_read,
    .llseek       = seq_lseek,
    .release      = single_release,
};

int init_module(void)  
{
    printk("Starting 1-methyamino-anthraquinone (aka Disperse Red 9)\n");
    statman = kmalloc(sizeof(struct statman),GFP_KERNEL); 
    memset(statman, 0, sizeof(struct statman));
    proc_create("paranoid", 0, NULL, &dr9_fops);
    net_if_proto.dev =  NULL;
    net_if_proto.type = htons(ETH_P_ALL); 
    net_if_proto.func = packet_func;
    dev_add_pack(&net_if_proto);
    printk("Disperse Red 9 now active\n");
    return 0;
}

void cleanup_module(void) 
{
    printk("Disperse Red 9 shutting down\n");
    dev_remove_pack(&net_if_proto);
    remove_proc_entry("paranoid", NULL); 
    kfree(statman);
    printk("Disperse Red 9 has terminated.\n");
}

MODULE_AUTHOR("JDO");
MODULE_LICENSE("GPL");
