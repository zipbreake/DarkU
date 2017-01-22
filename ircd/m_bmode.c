/*
 * IRC - Internet Relay Chat, ircd/s_bdd.c
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
 * $Id: m_bmode.c,v 1.1.1.1 2006/05/27 13:53:45 zipbreake Exp $
 */

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
 */
#include "config.h"

#include "client.h"
#include "ircd.h"
#include "channel.h"
#include "handlers.h"
#include "hash.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numnicks.h"
#include "parse.h"
#include "s_debug.h"
#include "send.h"
#include "s_bdd.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

CMD_FUNC(m_bmode)
{
	struct Channel *chptr;
    struct ModeBuf mbuf;
	struct db_reg *reg;

	assert(0 != IsServer(cptr));

	if (parc < 3)
		return 0;

	/* El canal no existe */
	if (!(chptr = FindChannel(parv[2])))
	{
		protocol_violation(sptr, "Attemped to set BMODE on inexistant channel (%s)", parv[2]);
		return 0;
	}

	/* Es un canal local */
	if (IsLocalChannel(chptr->chname))
	{
		protocol_violation(sptr, "Attemped to set BMODE on local channel");
		return 0;
	}

	/* Es un canal sin modos */
	if (IsModelessChannel(chptr->chname))
	{
		protocol_violation(sptr, "Attemped to set BMODE on modeless channel");
		return 0;
	}

    modebuf_init(&mbuf, sptr, cptr, chptr,
	   (MODEBUF_DEST_CHANNEL | /* Send mode to clients */
	    MODEBUF_DEST_SERVER  | /* Send mode to servers */
		MODEBUF_BOTMODE)	   /* Botmode */
	);

	mbuf.botmode_from = parv[1];

    mode_parse(&mbuf, cptr, sptr, chptr, parc - 3, parv + 3,
       (MODE_PARSE_SET    | /* Set the mode */
	MODE_PARSE_STRICT | /* Interpret it strictly */
	MODE_PARSE_FORCE)); /* And force it to be accepted */

	return modebuf_flush(&mbuf);
}
