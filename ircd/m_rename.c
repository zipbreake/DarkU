/*
 * IRC - Internet Relay Chat, ircd/m_rename.c
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
 * $Id: m_rename.c,v 1.3 2010/02/24 12:24:05 zipbreake Exp $
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

#include "IPcheck.h"
#include "client.h"
#include "handlers.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"
#include "s_bdd.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * m_rename
 *
 * Extraído del ircuH http://devel.irc-hispano.org
 *
 */

CMD_FUNC(m_rename)
{
	char tmpnick[NICKLEN+2];
	char nick[NICKLEN+1];
	struct Client *acptr, *bcptr;
	assert(0 != IsServer(cptr));

	if (parc < 2)
		return 0;

	if (!find_conf_byhost(cli_confs(cptr), cli_name(sptr), CONF_UWORLD))
		return 0;

	strncpy(tmpnick, parv[1], NICKLEN+2);

	if (strlen(tmpnick) > NICKLEN)
		tmpnick[NICKLEN] = '\0';

	sendcmdto_serv_butone(sptr, CMD_RENAME, cptr, "%s", tmpnick);

	if (0 == do_nick_name(tmpnick))
		return 0;

	if (FindServer(tmpnick))
		return 0;

	acptr = FindClient(tmpnick);

	if (!acptr || !MyUser(acptr))
		return 0;

	{
    unsigned int v[2], k[4], x[2];

    k[0] = k[1] = k[2] = k[3] = x[0] = x[1] = 0;

    v[0] = base64toint(cli_yxx(acptr));
    v[1] = base64toint(cli_yxx(&me));

    bcptr = acptr;

    do
    {
      tea(v, k, x);
      v[1] += 4096;
/*
** El 'if' que sigue lo necesitamos
** para que todos los valores tengan
** la misma probabilidad.
*/
      if (x[0] >= 4294000000ul)
	continue;
      sprintf(nick, "invitado-%.6d", (int)(x[0] % 1000000));
      bcptr = FindClient(nick);
    }
    while (bcptr);
  }

	cli_rhflags(acptr) |= RHFLAGS_RENAMED;
	set_nick_name(acptr, acptr, nick, 0, 0);
	{
		unsigned int old, oldrh;
		old = cli_flags(acptr);
		oldrh = cli_rhflags(acptr);
		cli_rhflags(acptr) &= ~(RHFLAGS_REGNICK | RHFLAGS_SUSPENDED);
		comprueba_privilegios(acptr);
		send_umode_out(acptr, acptr, old, oldrh, 0);
	}
	return 0;
}
