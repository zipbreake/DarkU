/*
 * IRC - Internet Relay Chat, ircd/m_quit.c
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
 * $Id: m_quit.c,v 1.3 2010/04/29 07:47:20 zipbreake Exp $
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

#include "channel.h"
#include "client.h"
#include "handlers.h"
#include "ircd.h"
#include "ircd_string.h"
#include "struct.h"
#include "s_misc.h"
#include "ircd_reply.h"
#include "ircd_features.h"

#include <assert.h>
#include <string.h>

extern void correct_colors(char *text);

/*
 * m_quit - client message handler 
 *
 * parv[0]        = sender prefix
 * parv[parc - 1] = comment
 */
CMD_FUNC(m_quit)
{
  static char *quitmsg = NULL;
  static int last_length = 0;
  int len;
  assert(0 != cptr);
  assert(0 != sptr);
  assert(cptr == sptr);

  if (cli_user(sptr)) {
    struct Membership* chan;
    for (chan = cli_user(sptr)->channel; chan; chan = chan->next_channel) {
      if (!IsZombie(chan) && !member_can_send_to_channel(chan))
        return exit_client(cptr, sptr, sptr, "Signed off");
    }
  }
  /* En caso de tener que mostrar un quit por defecto */
  if (feature_str(FEAT_HIDDEN_QUIT) && !(IsRegnick(sptr) || IsWebchatUser(sptr))) {
        return exit_client_msg(cptr, sptr, sptr, "Quit: %s", feature_str(FEAT_HIDDEN_QUIT));
  } else if (feature_str(FEAT_HIDDEN_QUIT_OPERS) && (IsAdmin(sptr) || IsCoadmin(sptr) || IsLocAdmin(sptr) || IsHelpOp(sptr) || IsModera(sptr))) {
        return exit_client_msg(cptr, sptr, sptr, "Quit: %s", feature_str(FEAT_HIDDEN_QUIT_OPERS));

  /* A partir de aqui recurrimos a los quits convencionales */
  } else if (parc > 1 && !BadPtr(parv[parc - 1])) {
	if ((len = strlen(parv[parc - 1])+1) > last_length)
	{
		if (quitmsg)
			free(quitmsg);
		quitmsg = (char *)MyMalloc(sizeof(char)*len);
		last_length = len;
	}
	strcpy(quitmsg, parv[parc - 1]);
	correct_colors(quitmsg);

	if (!process_badwords(quitmsg, BADWORDS_QUITMSG))
           return exit_client_msg(cptr, sptr, sptr, "Quit: %s", parv[parc - 1]);
	else
	   return exit_client(cptr, sptr, sptr, "Signed off (spam)");
  }
  else
    return exit_client(cptr, sptr, sptr, "Quit");
}


/*
 * ms_quit - server message handler template
 *
 * parv[0] = sender prefix
 * parv[parc - 1] = comment
 */
CMD_FUNC(ms_quit)
{
  assert(0 != sptr);
  assert(parc > 0);
  if (IsServer(sptr)) {
  	protocol_violation(sptr,"Server QUIT, not SQUIT?");
  	return 0;
  }
  /*
   * ignore quit from servers
   */
  return exit_client(cptr, sptr, sptr, parv[parc - 1]);
}
