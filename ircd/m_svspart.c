/*
 * IRC - Internet Relay Chat, ircd/m_svspart.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id: m_svspart.c,v 1.4 2009/12/03 11:45:46 zipbreake Exp $
 */

#include "config.h"
#include "channel.h"
#include "client.h"
#include "handlers.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "send.h"
#include <assert.h>
#include <string.h>


/*
 * m_svspart - server message handler
 *
 * parv[0] = sender prefix
 * parv[1] = numeric of client to act on
 * parv[2] = channel to force client to part
 */
CMD_FUNC(ms_svspart)
{
  struct Client *acptr;
  struct Channel *chptr;
  struct Membership *member;
  struct JoinBuf parts;
  unsigned int flags = 0;

  if (parc < 3) {
    protocol_violation(sptr, "Too few arguments for SVSPART");
    return need_more_params(sptr, "SVSPART");
  }

  if (!(acptr = findNUser(parv[1])))
    return 0;

  if (IsChannelService(acptr))
    return 0;

  if (!(chptr = get_channel(acptr, parv[2], CGT_NO_CREATE)))
    return 0;

  if (!(member = find_member_link(chptr, acptr)))
    return 0;

  /* init join/part buffer */
  joinbuf_init(&parts, acptr, acptr, JOINBUF_TYPE_PART, 0, 0);

  if (IsZombie(member))
    flags |= CHFL_ZOMBIE;

  if (!member_can_send_to_channel(member))
    flags |= CHFL_BANNED;

  joinbuf_join(&parts, chptr, flags);

  sendcmdto_serv_butone(sptr, CMD_SVSPART, cptr, "%s%s %s", acptr->cli_user->server->cli_yxx,
	acptr->cli_yxx, parv[2]);

  return joinbuf_flush(&parts);
}
