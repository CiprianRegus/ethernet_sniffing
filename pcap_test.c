#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6

struct sniff_ethernet
{
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};

void packet_callback(u_char *args, const struct pcap_pkthdr *header,
		     const u_char *packet)
{
	const struct sniff_ethernet *ethernet; /* The ethernet header */

	ethernet = (struct sniff_ethernet *)(packet);

	printf("Ethertype %x\n", ntohs(ethernet->ether_type));

	printf("Source: ");
	for (size_t i = 0; i < ETHER_ADDR_LEN; i++)
	{
		printf("%x ", ethernet->ether_shost[i]);
	}

	printf("\nDestination: ");
	for (size_t i = 0; i < ETHER_ADDR_LEN; i++)
	{
		printf("%x ", ethernet->ether_dhost[i]);
	}

	printf("\n");
}

int main()
{
	pcap_t *handle;
	pcap_if_t *pcap_devs;
	struct pcap_pkthdr header;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev_name = "enp4s0";
	const u_char *packet;
	char *dev;
	int ret;

	ret = pcap_findalldevs(&pcap_devs, errbuf);
	if (ret)
		return ret;

	for (; pcap_devs; pcap_devs = pcap_devs->next)
	{
		if (!strncmp(dev_name, pcap_devs->name, strlen(dev_name)))
			break;
	}

	handle = pcap_create(pcap_devs->name, errbuf);
	if (!handle)
	{
		fprintf(stderr, "No handle!\n");
		return -ENODEV;
	}

	ret = pcap_set_promisc(handle, 1);
	if (ret)
	{
		printf("err");
		return ret;
	}

	ret = pcap_activate(handle);
	if (ret)
	{
		printf("%s\n", pcap_geterr(handle));
		return ret;
	}

	if (pcap_datalink(handle) != DLT_EN10MB)
	{
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", pcap_devs->name);
		return -1;
	}

	pcap_loop(handle, 3, packet_callback, NULL);

	pcap_close(handle);

	return 0;
}