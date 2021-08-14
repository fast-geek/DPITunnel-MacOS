#include "dpitunnel-cli.h"

#include "netiface.h"
#include "profiles.h"
#include "utils.h"

extern int Interrupt_pipe[2];
extern std::atomic<bool> stop_flag;
extern struct Settings_s Settings;

struct Netlink {
	int id;
	struct nl_sock* socket;
	struct nl_cb* cb;
	int result;
};

struct Wifi {
	std::string ssid;
};

void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len) {
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));

	while(RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;

		rta = RTA_NEXT(rta,len);
	}
}

// Monitor when client changes interfaces. We need it to change profiles according to current net interface
void route_monitor_thread() {
	int sock;
	if((sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
		std::cerr << "Failed to open netlink socket. Errno: " << std::strerror(errno) << std::endl;
		return;
	}

	struct sockaddr_nl addr;
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = RTMGRP_IPV4_ROUTE;

	if(bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		std::cerr << "Failed to bind netlink socket. Errno: " << std::strerror(errno) << std::endl;
		close(sock);
		return;
	}

	// Make sokcet non-blocking
	if(fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK) == -1) {
		std::cerr << "Failed to make netlink socket non-blocking. Errno: " << std::strerror(errno) << std::endl;
		close(sock);
		return;
	}

	struct nlmsghdr *nlh;
	std::string buffer(8192, '\x00');
	nlh = (struct nlmsghdr *) &buffer[0];

	struct pollfd fds[2];

	// fds[0] is netlink socket
	fds[0].fd = sock;
	fds[0].events = POLLIN;

	// fds[1] is interrupt pipe
        fds[1].fd = Interrupt_pipe[0];
        fds[1].events = POLLIN;

	// Set poll() timeout
        int timeout = -1;

	int len;
	while(!stop_flag.load()) {
		int ret = poll(fds, 2, timeout);

		// Check state
		if (ret == -1) {
			std::cerr << "Poll error. Errno:" << std::strerror(errno) << std::endl;
			break;
		} else if (ret == 0)
			continue; // Timeout happened
		else {
			if(fds[0].revents & POLLERR ||
                           fds[0].revents & POLLHUP ||
                           fds[0].revents & POLLNVAL)
                                break;

			// Process netlink socket
                        if (fds[0].revents & POLLIN) {
				len = recv(sock, nlh, buffer.size(), 0);
				if(len <= 0) {
					std::cerr << "Netlink socket receive error. Errno: " << std::strerror(errno) << std::endl;
					break;
				}

				while ((NLMSG_OK(nlh, len)) && (nlh->nlmsg_type != NLMSG_DONE)) {
					if(nlh->nlmsg_type == RTM_NEWROUTE || nlh->nlmsg_type == RTM_DELROUTE) {
						// Check is it default route
						struct rtattr* tb[RTA_MAX + 1];
						struct rtmsg* r = (struct rtmsg *) NLMSG_DATA(nlh);
						parse_rtattr(tb, RTA_MAX, RTM_RTA(r), nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));
						if(!tb[RTA_DST] && !r->rtm_dst_len) {
							std::cout << "Detected network changes. Changing profile..." << std::endl;
							std::string temp;
							if(change_profile(&temp) == 0)
								std::cout << "Current profile: " << temp << std::endl;
							else
								std::cerr << "Failed to change profile" << std::endl;
						}
					}

					nlh = NLMSG_NEXT(nlh, len);
				}
			}

			fds[0].revents = 0;
			fds[1].revents = 0;
		}
	}

	close(sock);
}

std::string get_current_iface_name() {
	int sock;
	if((sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
		std::cerr << "Failed to open netlink socket. Errno: " << std::strerror(errno) << std::endl;
		return "";
	}

	std::string buffer(8192, '\x00');
	struct nlmsghdr* nlmsg = (struct nlmsghdr *) &buffer[0];

	// Fill header
	int msgseq = rand();
	nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	nlmsg->nlmsg_type = RTM_GETROUTE;
	nlmsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	nlmsg->nlmsg_seq = msgseq;
	nlmsg->nlmsg_pid = getpid();

	struct sockaddr_nl snl;
	memset(&snl, 0, sizeof(snl));
	snl.nl_family = AF_NETLINK;

	struct iovec iov;
	iov.iov_base = nlmsg;
	iov.iov_len = nlmsg->nlmsg_len;

	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &snl;
	msg.msg_namelen = sizeof(snl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	// Send request
	if(sendmsg(sock, &msg, 0) < 0) {
		std::cerr << "Failed to send netlink message. Errno: " << std::strerror(errno) << std::endl;
		close(sock);
		return "";
	}

	iov.iov_base = &buffer[0];
	iov.iov_len = buffer.size();

	// Receive response
	int result;
	if((result = recvmsg(sock, &msg, 0)) <= 0) {
		std::cerr << "Failed to receive from netlink socket. Errno: " << std::strerror(errno) << std::endl;
		close(sock);
		return "";
	}
	close(sock);

	while(NLMSG_OK(nlmsg, result) && nlmsg->nlmsg_type != NLMSG_DONE) {
		if(nlmsg->nlmsg_len < (int) sizeof(struct nlmsghdr) || nlmsg->nlmsg_len > result ||
			nlmsg->nlmsg_seq != msgseq) {
			nlmsg = NLMSG_NEXT(nlmsg, result);
			continue;
		}

		if(nlmsg->nlmsg_type == NLMSG_ERROR) {
			std::cerr << "nlmsg_type == NLMSG_ERROR" << std::endl;
			return "";
		}

		std::string interface(IF_NAMESIZE, '\x00');
		struct rtmsg *route_entry;
		struct rtattr *route_attribute;
		route_entry = (struct rtmsg *) NLMSG_DATA(nlmsg);
		route_attribute = (struct rtattr *) RTM_RTA(route_entry);
		int route_attribute_len = RTM_PAYLOAD(nlmsg);

		while(RTA_OK(route_attribute, route_attribute_len)) {
			if(route_attribute->rta_type == RTA_OIF) {
				if_indextoname(*(int *) RTA_DATA(route_attribute), &interface[0]);
				return std::string(interface.c_str());
			}

			route_attribute = RTA_NEXT(route_attribute, route_attribute_len);
		}

		nlmsg = NLMSG_NEXT(nlmsg, result);
	}

	std::cerr << "Failed to find default network interface" << std::endl;
	return "";
}

std::string get_current_wifi_name_ioctl(std::string iface_name) {
	int sock;
	if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		std::cerr << "Failed to open socket. Errno: " << std::strerror(errno) << std::endl;
		return "";
	}

	std::string essid(IW_ESSID_MAX_SIZE, '\x00');
	struct iwreq wreq;
	strncpy(wreq.ifr_ifrn.ifrn_name, iface_name.c_str(), IFNAMSIZ);
	strncpy(wreq.ifr_name, iface_name.c_str(), iface_name.size());
	wreq.u.essid.pointer = (caddr_t *) &essid[0];
	wreq.u.data.length = IW_ESSID_MAX_SIZE;
	wreq.u.data.flags = 0;
	if(ioctl(sock, SIOCGIWESSID, &wreq) == -1) {
		std::cerr << "Get ESSID ioctl failed. Errno: " << std::strerror(errno) << std::endl;
		close(sock);
		return "";
	}

	close(sock);
	return std::string(essid.c_str());
}

// Based on NetworkManager/src/platform/wifi/wifi-utils-nl80211.c
static void find_ssid(uint8_t *ies, uint32_t ies_len, uint8_t **ssid, uint32_t *ssid_len) {
#define WLAN_EID_SSID 0
	*ssid = NULL;
	*ssid_len = 0;

	while (ies_len > 2 && ies[0] != WLAN_EID_SSID) {
		ies_len -= ies[1] + 2;
		ies += ies[1] + 2;
	}
	if (ies_len < 2)
		return;
	if (ies_len < (uint32_t)(2 + ies[1]))
		return;

	*ssid_len = ies[1];
	*ssid = ies + 2;
}

static int get_scan_callback(struct nl_msg *msg, void *arg) {
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = (genlmsghdr *) nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *bss[NL80211_BSS_MAX + 1];
	static struct nla_policy bss_policy[NL80211_BSS_MAX + 1];
	bss_policy[NL80211_BSS_TSF].type = NLA_U64;
	bss_policy[NL80211_BSS_FREQUENCY].type = NLA_U32;
	bss_policy[NL80211_BSS_BEACON_INTERVAL].type = NLA_U16;
	bss_policy[NL80211_BSS_CAPABILITY].type = NLA_U16;
	bss_policy[NL80211_BSS_SIGNAL_MBM].type = NLA_U32;
	bss_policy[NL80211_BSS_SIGNAL_UNSPEC].type = NLA_U8;
	bss_policy[NL80211_BSS_STATUS].type = NLA_U32;
	bss_policy[NL80211_BSS_SEEN_MS_AGO].type = NLA_U32;
	char mac_addr[18];

	nla_parse(tb,
		NL80211_ATTR_MAX,
		genlmsg_attrdata(gnlh, 0),
		genlmsg_attrlen(gnlh, 0),
		NULL);

	if(!tb[NL80211_ATTR_BSS]) {
		std::cerr << "NL80211_ATTR_BSS missing" << std::endl;
		return NL_SKIP;
	}

	if(nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], bss_policy)) {
		std::cerr << "Failed to parse nested attributes" << std::endl;
		return NL_SKIP;
	}

	// Check is it associated AP
	if(bss[NL80211_BSS_STATUS] == NULL || nla_get_u32(bss[NL80211_BSS_STATUS]) != NL80211_BSS_STATUS_ASSOCIATED) return NL_SKIP;

	if(!bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
		std::cerr << "NL80211_BSS_INFORMATION_ELEMENTS missing" << std::endl;
		return NL_SKIP;
	}

	uint8_t *ssid;
	uint32_t ssid_len;

	find_ssid((uint8_t *) nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]),
		nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]),
		&ssid, &ssid_len);

	if(!ssid || !ssid_len) {
		std::cerr << "Failed to find SSID" << std::endl;
		return NL_SKIP;
	}

	(*(Wifi *) arg).ssid = std::string((const char *) ssid, ssid_len);

	return NL_SKIP;
}

static int finish_handler(struct nl_msg *msg, void *arg) {
	int *ret = (int *) arg;
	*ret = 0;
	return NL_SKIP;
}

static int init_nl80211(Netlink* nl, Wifi* w) {
	nl->socket = nl_socket_alloc();
	if (!nl->socket) {
		std::cerr << "Failed to open netlink socket" << std::endl;
		return -ENOMEM;
	}

	nl_socket_set_buffer_size(nl->socket, 8192, 8192);

	if (genl_connect(nl->socket)) {
		std::cerr << "Failed to connect to netlink socket" << std::endl;
		nl_close(nl->socket);
		nl_socket_free(nl->socket);
		return -ENOLINK;
	}

	nl->id = genl_ctrl_resolve(nl->socket, "nl80211");
	if (nl->id < 0) {
		std::cerr << "Nl80211 interface not found" << std::endl;
		nl_close(nl->socket);
		nl_socket_free(nl->socket);
		return -ENOENT;
	}

	nl->cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (nl->cb == NULL) {
		std::cerr << "Failed to allocate netlink callback" << std::endl;
		nl_close(nl->socket);
		nl_socket_free(nl->socket);
		return -ENOMEM;
	}

	nl_cb_set(nl->cb, NL_CB_VALID , NL_CB_CUSTOM, get_scan_callback, w);
	nl_cb_set(nl->cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &(nl->result));

	return 0;
}

std::string get_current_wifi_name_netlink(std::string iface_name) {
	Netlink nl;
	Wifi w;

	if(init_nl80211(&nl, &w) != 0) {
		std::cerr << "Error initializing netlink 802.11" << std::endl;
		return "";
	}

	nl.result = 1;

	// Get scan results
	struct nl_msg* msg = nlmsg_alloc();
	if(!msg) {
		std::cerr << "Failed to allocate netlink message" << std::endl;
		nl_cb_put(nl.cb);
		nl_close(nl.socket);
		nl_socket_free(nl.socket);
		return "";
	}

	genlmsg_put(msg,
		NL_AUTO_PORT,
		NL_AUTO_SEQ,
		nl.id,
		0,
		NLM_F_DUMP,
		NL80211_CMD_GET_SCAN,
		0);

	int ifindex = if_nametoindex(iface_name.c_str());
	if(ifindex == 0) {
		std::cerr << "if_nametoindex failed. Errno: " << std::strerror(errno) << std::endl;
		nl_cb_put(nl.cb);
		nl_close(nl.socket);
		nl_socket_free(nl.socket);
		nlmsg_free(msg);
		return "";
	}

	nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);
	nl_send_auto(nl.socket, msg);
	while (nl.result > 0) { nl_recvmsgs(nl.socket, nl.cb); }
	nlmsg_free(msg);

	return w.ssid;
}

std::string get_current_wifi_name(std::string iface_name) {
	std::string response;
	if((response = get_current_wifi_name_ioctl(iface_name)).empty())
		response = get_current_wifi_name_netlink(iface_name);

	return response;
}
