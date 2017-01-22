/*
 * IRC - Internet Relay Chat, ircd/m_ghost.c
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
 * $Id: m_ghost.c,v 1.4 2009/11/19 22:15:36 zipbreake Exp $
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

int verifica_clave_nick(char *nickname, char *password, char *realpass);

CMD_FUNC(m_ghost)
{
	struct Client *acptr;
	struct db_reg *reg;
	char *botname;
	assert(0 == IsServer(cptr));

	if ((reg = db_buscar_registro(BDD_BOTS, BDD_BOTS_NICKSERV)) && (reg->valor))
		botname = reg->valor;
	else
		botname = cli_name(&me);

	if (parc < 2) {
sintaxis:
		sendbotcmd(botname, CMD_NOTICE, cptr, "%C :*** Sintaxis: /GHOST <nick> <clave>", cptr);
		return need_more_params(cptr, "GHOST");
	}

	if (!(acptr = FindClient(parv[1]))) {
		sendbotcmd(botname, CMD_NOTICE, cptr, "%C :*** Error: El nick %s no está en uso.", cptr, parv[1]);
		return 0;
	}

	if (!(reg = db_buscar_registro(BDD_NICKS, parv[1])) || !(reg->valor)) {
		sendbotcmd(botname, CMD_NOTICE, cptr, "%C :*** Error: El nick %s no está registrado en BDD.",
			cptr, parv[1]);
		return 0;
	}
	/*
	 * 24/07/04 RyDeN             (u2.10.RH.02.107)                    FIX
	 * -------------------------------------------------------------------
	 *  Arreglado un error en el m_ghost.
	 *  
	 * Bug descubierto por DIaN
	 */
	if (acptr == cptr)
	{
	  sendbotcmd(botname, CMD_NOTICE, cptr, "%C :*** Error: No puedes hacerte ghost a ti mismo", cptr);
	  return 0;
	}

	if (parc == 2) {
		if ((cli_passwd(cptr) == NULL) || !(verifica_clave_nick(reg->clave, cli_passwd(cptr), reg->valor)))
			goto sintaxis;
	} else if (!(verifica_clave_nick(reg->clave, parv[2], reg->valor))) {
		sendbotcmd(botname, CMD_NOTICE, cptr, "%C :*** Error: Clave incorrecta.", cptr);
		return 0;
	} else {
		char who[NICKLEN+2];

		if (!IsRegistered(cptr))
			sprintf(who, "%s!", cli_name(acptr));
		else
			strcpy(who, cli_name(cptr));

		sendcmdto_serv_butone(&me, CMD_GHOST, NULL,
			"%s %s", cli_name(acptr), who);

		if (MyUser(acptr)) {
			sendcmdto_one(&me, CMD_NOTICE, acptr,
				"%C :*** Sesión fantasma liberada por %s.",
				acptr, who);
		}
		sendbotcmd(botname, CMD_NOTICE, cptr,
			"%C :*** Sesión fantasma del nick %s liberada.",
			cptr, cli_name(acptr));
		exit_client_msg(acptr, acptr, &me, "Sesión fantasma liberada por %s", who);
	}
	return 0;
}

CMD_FUNC(ms_ghost)
{
  struct Client *acptr;
  assert(0 != IsServer(cptr));
    
  if (parc < 3)
  {
    return 0;
  }
    
	sendcmdto_serv_butone(&me, CMD_GHOST, cptr,
			"%s %s", parv[1], parv[2]);
	
	
	if ((acptr = FindClient(parv[1])) && MyUser(acptr)) {
		sendcmdto_one(&me, CMD_NOTICE, acptr,
			"%C :*** Sesión fantasma liberada por %s.",
			acptr, parv[2]);
	}
	if (acptr)
	{
	  exit_client_msg(acptr, acptr, &me, "Sesión fantasma liberada por %s", parv[2]);
	}
	return 0;
}
