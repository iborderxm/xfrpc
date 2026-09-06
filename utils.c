
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <stdbool.h>

#include "utils.h"
#include "ssl_compat.h"
#include "debug.h"

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

/* 全局随机数生成器：CTR_DRBG，首次使用时惰性初始化。
 * xfrpc 为单线程事件循环模型，惰性初始化无需加锁。
 *
 * 熵源说明：mbedTLS 3.6.x 平台熵源（entropy_poll.c）的 getrandom()
 * 分支仅在 __GLIBC__ 下编译，musl 构建退化为 stdio fopen/fread 读
 * /dev/urandom；且 entropy 模块中任一注册熵源失败都会令整个采集
 * 流程失败、无冗余回退。嵌入式厂商固件上该路径不可靠（实测
 * mipsel 设备报 "Failed to generate random IV"）。因此这里不使用
 * mbedtls_entropy_* 模块，直接以原始 open/read 系统调用读取
 * /dev/urandom 作为 CTR_DRBG 播种源——与 OpenSSL/Go 运行时一致，
 * 是各平台上最基础可靠的熵源路径。 */
static mbedtls_ctr_drbg_context g_ctr_drbg;
static int g_rng_inited = 0;

/**
 * CTR_DRBG 熵源回调（mbedtls_ctr_drbg_seed 的 f_entropy 签名：
 * 三参数、无 olen 出参，须填满 len 字节）。
 * 用原始系统调用读取 /dev/urandom，不经 stdio，
 * 失败时记录精确 errno 便于现场设备定位。
 *
 * @return 0 成功，MBEDTLS_ERR_ENTROPY_SOURCE_FAILED 表示读取失败
 */
static int urandom_entropy_poll(void *data, unsigned char *output, size_t len)
{
	(void)data;

	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		debug(LOG_ERR, "open /dev/urandom failed: errno=%d", errno);
		return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
	}

	size_t got = 0;
	while (got < len) {
		ssize_t r = read(fd, output + got, len - got);
		if (r <= 0) {
			debug(LOG_ERR, "read /dev/urandom failed: r=%d errno=%d",
			      (int)r, errno);
			close(fd);
			return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
		}
		got += (size_t)r;
	}

	close(fd);
	return 0;
}

/**
 * 全局随机数生成函数（mbedTLS f_rng 签名）。
 * 首次调用时以 /dev/urandom（原始系统调用）播种 CTR_DRBG；
 * p_rng 参数仅为满足 mbedTLS 回调签名，内部未使用。
 *
 * @param p_rng      mbedTLS 回调上下文（忽略）
 * @param output     随机数输出缓冲区
 * @param output_len 需要的随机数字节数
 * @return 0 成功，非 0 为 mbedTLS 错误码
 */
int xfrpc_random(void *p_rng, unsigned char *output, size_t output_len)
{
	(void)p_rng;

	if (!g_rng_inited) {
		int ret;
		mbedtls_ctr_drbg_init(&g_ctr_drbg);
		/* 个性化字符串可为任意固定值，用于增强 DRBG 实例隔离 */
		ret = mbedtls_ctr_drbg_seed(&g_ctr_drbg, urandom_entropy_poll,
					    NULL,
					    (const unsigned char *)"xfrpc", 5);
		if (ret != 0) {
			debug(LOG_ERR, "CTR_DRBG seed failed: -0x%04x", -ret);
			mbedtls_ctr_drbg_free(&g_ctr_drbg);
			return ret;
		}
		g_rng_inited = 1;
	}

	return mbedtls_ctr_drbg_random(&g_ctr_drbg, output, output_len);
}

/**
 * High precision sleep function using select
 * 
 * This function provides a more precise sleep mechanism than standard sleep()
 * by using select() system call. It can sleep for specified seconds and microseconds.
 *
 * @param s Number of seconds to sleep
 * @param u Number of microseconds to sleep (1 second = 1,000,000 microseconds)
 */
void s_sleep(unsigned int s, unsigned int u)
{
	struct timeval timeout;
	timeout.tv_sec = s;
	timeout.tv_usec = u;
	select(0, NULL, NULL, NULL, &timeout);
}

/**
 * Validates IPv4 address string format
 * 
 * This function checks if the given string represents a valid IPv4 address
 * in dotted decimal notation (e.g., "192.168.1.1").
 *
 * @param ip_address String containing the IP address to validate
 * @return 1 if address is valid, 0 if invalid
 */
int is_valid_ip_address(const char *ip_address) 
{
	if (!ip_address) {
		return 0;
	}
	
	struct sockaddr_in sa;
	return inet_pton(AF_INET, ip_address, &(sa.sin_addr));
}

/**
 * Gets the MAC address of a specified network interface
 * 
 * This function retrieves the hardware (MAC) address of a network interface
 * and formats it as a string of uppercase hexadecimal digits.
 *
 * @param net_if_name Name of network interface (e.g., "br-lan", "eth0")
 * @param mac Output buffer to store MAC address string
 * @param mac_len Length of output buffer (must be >= 13 bytes for MAC XXYYZZAABBCC)
 * @return 0 on success, 1 on error (invalid parameters or system calls failed)
 */
int get_net_mac(const char *net_if_name, char *mac, int mac_len) 
{
	struct ifreq ifreq;
	int sock;

	// Validate input parameters: 12 hex chars + 1 null terminator = 13 bytes minimum
	if (!net_if_name || !mac || mac_len < 13) {
		return 1;
	}

	// Create socket for interface communication
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket creation failed");
		return 1;
	}

	// Prepare interface request structure
	memset(&ifreq, 0, sizeof(ifreq));
	strncpy(ifreq.ifr_name, net_if_name, IFNAMSIZ - 1);

	// Get hardware address
	if (ioctl(sock, SIOCGIFHWADDR, &ifreq) < 0) {
		perror("ioctl SIOCGIFHWADDR failed");
		close(sock);
		return 1;
	}

	// Format MAC address as string
	for (int i = 0; i < 6; i++) {
		snprintf(mac + (i * 2), mac_len - (i * 2), "%02X", 
				(unsigned char)ifreq.ifr_hwaddr.sa_data[i]);
	}

	close(sock);
	return 0;
}

/**
 * Displays information about all network interfaces on the system
 * 
 * This function prints details for each network interface including:
 * - Interface name
 * - Address family (AF_PACKET, AF_INET, AF_INET6)
 * - IP address (for AF_INET/AF_INET6 interfaces)
 * - Packet statistics (for AF_PACKET interfaces)
 *
 * @return Number of interfaces found, or -1 on error
 */
int show_net_ifname()
{
	struct ifaddrs *ifaddr = NULL, *ifa = NULL;
	int family, s, n = 0;
	char host[NI_MAXHOST];

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		return -1;
	}

	for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
		if (ifa->ifa_addr == NULL)
			continue;

		family = ifa->ifa_addr->sa_family;

		// Display interface name and address family
		printf("%-8s %s (%d)\n",
			   ifa->ifa_name,
			   (family == AF_PACKET) ? "AF_PACKET" :
			   (family == AF_INET) ? "AF_INET" :
			   (family == AF_INET6) ? "AF_INET6" : "???",
			   family);

		// Handle IP addresses
		if (family == AF_INET || family == AF_INET6) {
			s = getnameinfo(ifa->ifa_addr,
						  (family == AF_INET) ? sizeof(struct sockaddr_in) :
											  sizeof(struct sockaddr_in6),
						  host, NI_MAXHOST,
						  NULL, 0, NI_NUMERICHOST);
			if (s != 0) {
				fprintf(stderr, "getnameinfo() failed: %s\n", gai_strerror(s));
				freeifaddrs(ifaddr);
				return -1;
			}
			printf("\t\taddress: <%s>\n", host);
		}
		// Handle packet statistics
		else if (family == AF_PACKET && ifa->ifa_data != NULL) {
			struct rtnl_link_stats *stats = (struct rtnl_link_stats *)ifa->ifa_data;
			printf("\t\ttx_packets = %10u; rx_packets = %10u\n"
				   "\t\ttx_bytes   = %10u; rx_bytes   = %10u\n",
				   stats->tx_packets, stats->rx_packets,
				   stats->tx_bytes, stats->rx_bytes);
		}
	}

	freeifaddrs(ifaddr);
	return n;
}

/**
 * Gets the primary network interface name of the system
 * 
 * This function attempts to find the primary network interface name by:
 * 1. First looking for common router interfaces (br-lan or br0)
 * 2. Falling back to first non-loopback interface if router interfaces not found
 *
 * @param if_buf Output buffer to store interface name
 * @param blen Length of output buffer (must be >= 8 bytes)
 * @return 0 on success, -1 on invalid parameters, 1 if no interface found
 */
int get_net_ifname(char *if_buf, int blen)
{
	// Validate input parameters
	if (if_buf == NULL || blen < 8) {
		return -1;
	}

	struct ifaddrs *ifaddr = NULL, *ifa = NULL;
	int family;
	char backup_ifname[IFNAMSIZ] = {0};
	
	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		return 1;
	}

	// Iterate through all interfaces
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) {
			continue;
		}

		family = ifa->ifa_addr->sa_family;

		if (family == AF_INET) {
			// Check for router specific interfaces
			if (strcmp(ifa->ifa_name, "br-lan") == 0 || 
				strcmp(ifa->ifa_name, "br0") == 0) {
				strncpy(if_buf, ifa->ifa_name, blen);
				freeifaddrs(ifaddr);
				return 0;
			}
		} else if (family == AF_PACKET && 
				  ifa->ifa_data != NULL && 
				  strcmp(ifa->ifa_name, "lo") != 0) {
			// Store first non-loopback interface as backup
			strncpy(backup_ifname, ifa->ifa_name, IFNAMSIZ-1);
		}
	}

	// Use backup interface if router interfaces not found
	if (backup_ifname[0] != '\0') {
		strncpy(if_buf, backup_ifname, blen);
		freeifaddrs(ifaddr);
		return 0;
	}

	freeifaddrs(ifaddr);
	return 1;
}

/**
 * Converts domain name to lowercase and validates format
 * 
 * This function takes a domain name string and:
 * 1. Converts all characters to lowercase until '/' is encountered
 * 2. Validates that the domain has at least one dot (.)
 * 3. Copies the result to the output buffer
 *
 * Example: wWw.Baidu.com/China -> www.baidu.com/China
 *
 * @param dname Input domain name string
 * @param udname_buf Output buffer for unified domain name
 * @param udname_buf_len Length of output buffer
 * @return 0 on success, 1 on failure (invalid domain or buffer too small)
 */
int dns_unified(const char *dname, char *udname_buf, int udname_buf_len)
{
	// Validate input parameters
	if (!dname || !udname_buf || udname_buf_len < strlen(dname) + 1) {
		return 1;
	}

	const int dlen = strlen(dname);
	bool has_dot = false;

	// Process each character until '/' or end of string.
	// The two return points are intentional: when a '/' is found we must
	// null-terminate at that position (stripping the path component), whereas
	// if no '/' is present we null-terminate at the full string length below.
	for (int i = 0; i < dlen; i++) {
		if (dname[i] == '/') {
			udname_buf[i] = '\0';
			// Domain must contain at least one dot
			return has_dot ? 0 : 1;
		}

		if (dname[i] == '.' && i != dlen - 1) {
			has_dot = true;
		}

		udname_buf[i] = tolower(dname[i]);
	}

	// Ensure the output is always null-terminated when no '/' was found
	udname_buf[dlen] = '\0';

	// Domain must contain at least one dot
	return has_dot ? 0 : 1;
}