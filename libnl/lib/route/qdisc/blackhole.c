/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * Copyright (c) 2003-2011 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @ingroup qdisc
 * @defgroup qdisc_blackhole Blackhole
 * @{
 */

#define _GNU_SOURCE

#include <netlink-private/netlink.h>
#include <netlink/netlink.h>
#include <netlink-private/route/tc-api.h>

static struct rtnl_tc_ops blackhole_ops = {
	.to_kind		= "blackhole",
	.to_type		= RTNL_TC_TYPE_QDISC,
};

static void __init blackhole_init(void)
{
	rtnl_tc_register(&blackhole_ops);
}

static void __exit blackhole_exit(void)
{
	rtnl_tc_unregister(&blackhole_ops);
}

/** @} */
