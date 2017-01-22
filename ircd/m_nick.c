/*
 * IRC - Internet Relay Chat, ircd/m_nick.c
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
 * $Id: m_nick.c,v 1.13 2010/04/29 11:22:59 zipbreake Exp $
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

char *cifranick(char *nickname, char *password);

int verifica_clave_nick(char *nickname, char *password, char *realpass)
{
  unsigned long v[2], w[2], k[4], hispass[2];
  char tmpnick[8 * ((NICKLEN + 8) / 8) + 1];
  char tmppass[24 + 1];
  unsigned int *p = (unsigned int *)tmpnick;
  int count = (NICKLEN + 8)/8;
  char c;

  memset(tmppass, 0, sizeof(tmppass));
  strncpy(tmppass, password, sizeof(tmppass)-1);
  strncat(tmppass, "AAAAAAAAAAAAAAAAAAAAAAAA", sizeof(tmppass)-strlen(tmppass)-1);

  memset(tmpnick, 0, sizeof(tmpnick));
  strncpy(tmpnick, nickname, sizeof(tmpnick));

  k[3] = base64toint(tmppass+18);
  tmppass[18] = '\0';

  k[2] = base64toint(tmppass+12);
  tmppass[12] = '\0';

  k[1] = base64toint(tmppass+6);
  tmppass[6] = '\0';

  k[0] = base64toint(tmppass);

  w[0] = w[1] = 0;
	
  while (count--)
  {
    v[0] = ntohl(*p++);
    v[1] = ntohl(*p++);
    tea(v, k, w);
  }

  c = realpass[6];
  hispass[1] = base64toint(realpass+6);
  realpass[6] = '\0';
  hispass[0] = base64toint(realpass);
  realpass[6] = c;

  return ((w[0] == hispass[0]) && (w[1] == hispass[1]));
}

/*
 * m_nick - message handler for local clients
 * parv[0] = sender prefix
 * parv[1] = nickname
 * parv[2] = mount: si esta definido, puede ser
 *                  la clave del nick.
 *                  (compatibilidad con algunos
 *                  clientes, como BitchX).
 */

struct __relaciones_mf__
{
  unsigned int flag;
  unsigned int dbflag;
}
relacion_flags_tabla[] = {
  { RHFLAGS_COADM,	OPER_ALLOWED_c },
  { RHFLAGS_ADM,	OPER_ALLOWED_a },
  { RHFLAGS_LOCADMIN,	OPER_ALLOWED_A },
  { RHFLAGS_MODERA,	OPER_ALLOWED_m },
  { RHFLAGS_HELPOP,	OPER_ALLOWED_h },
  { RHFLAGS_BOT,	OPER_ALLOWED_B },
  { RHFLAGS_USERBOT,	OPER_ALLOWED_b },
  { 0, 0 }
};

CMD_FUNC(m_nick)
{
  struct Client* acptr;
  static char    nick[NICKLEN + 2];
  static char	 tmpnick[NICKLEN + 2];
  char*          s, *c;
  const char*    client_name;
  unsigned long fold = cli_flags(sptr);
  unsigned long frhold = cli_rhflags(sptr);
  int clave_ok = 0, hacer_ghost = 0, utiliza_clave = 0, nick_en_uso = 0, nick_suspendido = 0;
  int retardo = 0;
  struct db_reg *reg;
  char *botname;

  assert(0 != cptr);
  assert(cptr == sptr);

  /*
   * parv[0] will be empty for clients connecting for the first time
   */
  client_name = (*(cli_name(sptr))) ? cli_name(sptr) : "*";

  if (parc < 2) {
    send_reply(sptr, ERR_NONICKNAMEGIVEN);
    return 0;
  }

  /*
   * Don't let them send make us send back a really long string of
   * garbage
   */
#if 0
  arg = parv[1];
  if (strlen(arg) > NICKLEN)
    arg[NICKLEN] = '\0';

  if ((s = strchr(arg, '~')))
    *s = '\0';
#endif

  strncpy(tmpnick, parv[1], NICKLEN+2);
  tmpnick[NICKLEN+1] = '\0';

  if (strlen(tmpnick) > NICKLEN)
	 tmpnick[NICKLEN] = '\0';

  if ((s = strchr(tmpnick, '~')))
	 *s = '\0';

  strcpy(nick, tmpnick);

  /*
   * If do_nick_name() returns a null name OR if the server sent a nick
   * name and do_nick_name() changed it in some way (due to rules of nick
   * creation) then reject it. If from a server and we reject it,
   * and KILL it. -avalon 4/4/92
   */
  if (0 == do_nick_name(nick)) {
    send_reply(sptr, ERR_ERRONEUSNICKNAME, tmpnick);
    return 0;
  }

  if (!(cli_rhflags(sptr) & RHFLAGS_RENAMED) &&
      (strcasecmp(nick, "invitado-000000") >= 0) && (strcasecmp(nick, "invitado-999999") <= 0))
  {
    if (FindClient(nick))
    {
      send_reply(sptr, ERR_NICKNAMEINUSE, nick);
    }
    else
    {
      send_reply(sptr, ERR_ERRONEUSNICKNAME, nick);
    }
    return 0;
  }
  /* 
   * Check if this is a LOCAL user trying to use a reserved (Juped)
   * nick, if so tell him that it's a nick in use...
   */
  if (isNickJuped(nick)) {
    send_reply(sptr, ERR_NICKNAMEINUSE, nick);
    return 0;                        /* NICK message ignored */
  }

  if (!(acptr = FindClient(nick)))
  {
    /*
     * No collisions, all clear...
     */

ghost:

    if ((reg = db_buscar_registro(BDD_BOTS, BDD_BOTS_NICKSERV)) && (reg->valor))
    {
      botname = reg->valor;
    }
    else
    {
      botname = cli_name(&me);
    }

    if ((reg = db_buscar_registro(BDD_NICKS, nick)) && (reg->valor))
    {
      c = strrchr(reg->valor, '*');

      /* Forbid */
      if (c && (*++c == '\0'))
      {
        sendbotcmd(botname, CMD_NOTICE, sptr,
            "%C :*** El nick %s está prohibido de ser utilizado.",
            sptr, nick);
        send_reply(sptr, ERR_NICKNAMEINUSE, nick);
        return 0;
      }

      s = strrchr(reg->valor, '+');

      /* Suspend */
      if (s && (*(s+1) == '\0'))
      {
        nick_suspendido = 1;
        *s = '\0';
      }

      c = parv[1]+strlen(nick);
      if (*c != '\0')
      {
        if (*c == '!' || *c == ':')
        {
          if (*(c+1) != '\0')
          {
            utiliza_clave = 1;
          }
          if (*c == '!')
          {
            hacer_ghost = 1;
          }
        }
	  
        if (utiliza_clave)
        {
          c++;
        }
      }

      if (!utiliza_clave)
      {
        c = cli_passwd(cptr);
      }

      if (c != NULL)
      {
        clave_ok = verifica_clave_nick(reg->clave, c, reg->valor);
      }

      /* Puede que esté en parv[2]... */
      if (!(utiliza_clave) && parv[2])
      {
        /* Para que quede constancia de que se ha probado con esta clave... en el caso de que falle. */
        utiliza_clave = 1;
        clave_ok = verifica_clave_nick(reg->clave, parv[2], reg->valor);
      }
      if (nick_suspendido)
      {
        *s = '+';
      }

      if (!clave_ok)
      {
        if (!utiliza_clave)
        {
          if (!nick_en_uso)
          {
            sendbotcmd(botname, CMD_NOTICE, sptr,
                "%C :*** El nick %s está Registrado, necesitas contraseña.",
                sptr, nick);
            sendbotcmd(botname, CMD_NOTICE, sptr,
                "%C :*** Utiliza /NICK %s:clave para identificarte.",
                sptr, nick);
          }
          send_reply(sptr, ERR_NICKNAMEINUSE, nick);
          return 0;
        }

        else
        {
          if (!nick_en_uso)
          {
            sendbotcmd(botname, CMD_NOTICE, sptr,
                "%C :*** Contraseña Incorrecta para el nick %s.",
                sptr, nick);
            sendbotcmd(botname, CMD_NOTICE, sptr,
                "%C :*** Utiliza /NICK %s:clave para identificarte.",
                sptr, nick);
          }
          send_reply(sptr, ERR_NICKNAMEINUSE, nick);
          return 0;
        }
      } /* if (!clave_ok) */

      else
      {
        retardo = !(CurrentTime >= cli_nextnick(sptr) || (cli_flags(sptr) & FLAGS_CHSERV));

        if (!retardo)
        {
          /* GHOST */

          if (hacer_ghost && nick_en_uso)
          {
            char who[NICKLEN+2];

            if (!IsRegistered(sptr))
            {
              snprintf(who, NICKLEN+1, "%s!", nick);
            }
            else
            {
              strcpy(who, cli_name(sptr));
            }

            sendcmdto_serv_butone(&me, CMD_GHOST, NULL, "%s %s", cli_name(acptr), who);
            if (MyUser(acptr))
            {
              sendcmdto_one(&me, CMD_NOTICE, acptr,
                  "%C :Sesión fantasma liberada por %s.",
                  acptr, who);
            }
            sendbotcmd(botname, CMD_NOTICE, sptr,
                "%C :*** Sesión fantasma del nick %s liberada.",
                sptr, nick);
            exit_client_msg(cptr, acptr, &me, "Sesión fantasma liberada por %s", who);
          }

          clave_ok = 2;
        } /* if (!retardo) */

        else if (nick_en_uso)
        {
          send_reply(sptr, ERR_NICKNAMEINUSE, nick);
          return 0;
        }
      }
    } /* if ((reg = db_buscar_registro(BDD_NICKS, nick)) && (reg->valor)) */

    else if (nick_en_uso)
    {
      send_reply(sptr, ERR_NICKNAMEINUSE, nick);
      return 0;
    }

    if (!retardo && IsRegistered(sptr))
    {
      cli_rhflags(sptr) &= ~(RHFLAGS_REGNICK | RHFLAGS_SUSPENDED);
      comprueba_privilegios(sptr);
      send_umode_out(sptr, sptr, fold, frhold, 0);
      frhold = cli_rhflags(sptr);
    }

    if (set_nick_name(cptr, sptr, nick, parc, parv) != 5)
    {
      cli_user(sptr)->dbflags = 0;
      if (clave_ok == 2)
      {
        struct db_reg *reg;

        if (!nick_suspendido)
        {
          sendbotcmd(botname, CMD_NOTICE, sptr,
              "%C :*** Contraseña aceptada. Bienvenid@ a casa ;)",
              sptr);
          cli_rhflags(sptr) |= RHFLAGS_REGNICK;
        }
        else
        {
          sendbotcmd(botname, CMD_NOTICE, sptr,
              "%C :*** Este nick ha sido SUSPENDido",
              sptr);
          cli_rhflags(sptr) |= RHFLAGS_SUSPENDED;
        }
	/* Este registrado o suspendido le damos el +z si esta la feature secure */
        if (feature_bool(FEAT_SECURE_MODE))
            cli_rhflags(sptr) |= RHFLAGS_SECURE;

        if ((reg = db_buscar_registro(BDD_FLAGS, cli_name(sptr))) && (reg->valor) &&
            IsDigit(*(reg->valor)))
        {
          assert(0 != cli_user(sptr));
			    
          cli_user(sptr)->dbflags = atoi(reg->valor);
          if (cli_user(sptr)->dbflags != 0)
          {
            int i;
            for (i = 0; relacion_flags_tabla[i].flag; i++)
            {
              if (cli_user(sptr)->dbflags & relacion_flags_tabla[i].dbflag)
              {
                cli_rhflags(sptr) |= relacion_flags_tabla[i].flag;
              }
            }
          }
        }
      }
      comprueba_privilegios(sptr);
      if (IsRegistered(sptr))
      {
        send_umode_out(sptr, sptr, fold, frhold, 0);
      }
    }
    return 0;
  }

  if (IsServer(acptr))
  {
    send_reply(sptr, ERR_NICKNAMEINUSE, nick);
    return 0;                        /* NICK message ignored */
  }
  /*
   * If acptr == sptr, then we have a client doing a nick
   * change between *equivalent* nicknames as far as server
   * is concerned (user is changing the case of his/her
   * nickname or somesuch)
   */
  if (acptr == sptr) {
    /*
     * If acptr == sptr, then we have a client doing a nick
     * change between *equivalent* nicknames as far as server
     * is concerned (user is changing the case of his/her
     * nickname or somesuch)
     */
    if (0 != strcmp(cli_name(acptr), nick)) {
      /*
       * Allows change of case in his/her nick
       */
      return set_nick_name(cptr, sptr, nick, parc, parv);
    }
    /*
     * This is just ':old NICK old' type thing.
     * Just forget the whole thing here. There is
     * no point forwarding it to anywhere,
     * especially since servers prior to this
     * version would treat it as nick collision.
     */
    return 0;
  }
  /*
   * Note: From this point forward it can be assumed that
   * acptr != sptr (point to different client structures).
   */
  assert(acptr != sptr);
  /*
   * If the older one is "non-person", the new entry is just
   * allowed to overwrite it. Just silently drop non-person,
   * and proceed with the nick. This should take care of the
   * "dormant nick" way of generating collisions...
   *
   * XXX - hmmm can this happen after one is registered?
   */
  if (IsUnknown(acptr) && MyConnect(acptr)) {
    ++ServerStats->is_ref;
    IPcheck_connect_fail(cli_ip(acptr));
    exit_client(cptr, acptr, &me, "Overridden by other sign on");
    return set_nick_name(cptr, sptr, nick, parc, parv);
  }
  /*
   * NICK is coming from local client connection. Just
   * send error reply and ignore the command.
   */

  c = parv[1]+strlen(nick);
  if (*c != '\0')
  {
    if (*c == '!' || *c == ':')
    {
      if (*(c+1) != '\0')
      {
        utiliza_clave = 1;
      }
      if (*c == '!')
      {
        hacer_ghost = 1;
      }
    }
    if (utiliza_clave)
    {
      c++;
    }
  }
  if (hacer_ghost)
  {
    nick_en_uso = 1;
    goto ghost;
  }

  send_reply(sptr, ERR_NICKNAMEINUSE, nick);
  return 0;                        /* NICK message ignored */
}


/*
 * ms_nick - server message handler for nicks
 * parv[0] = sender prefix
 * parv[1] = nickname
 *
 * If from server, source is client:
 *   parv[2] = timestamp
 *
 * Source is server:
 *   parv[2] = hopcount
 *   parv[3] = timestamp
 *   parv[4] = username
 *   parv[5] = hostname
 *   parv[6] = umode (optional)
 *   parv[parc-3] = IP#                 <- Only Protocol >= 10
 *   parv[parc-2] = YXX, numeric nick   <- Only Protocol >= 10
 *   parv[parc-1] = info
 *   parv[0] = server
 */
CMD_FUNC(ms_nick)
{
  struct Client* acptr;
  char           nick[NICKLEN + 2];
  time_t         lastnick = 0;
  int            differ = 1;

  assert(0 != cptr);
  assert(0 != sptr);
  assert(IsServer(cptr));
  
  if ((IsServer(sptr) && parc < 8) || parc < 3) {
    sendto_opmask_butone(0, SNO_OLDSNO, "bad NICK param count for %s from %C",
			 parv[1], cptr);
    return need_more_params(sptr, "NICK");
  }

  ircd_strncpy(nick, parv[1], NICKLEN);
  nick[NICKLEN] = '\0';

  if (IsServer(sptr)) {
    lastnick = atoi(parv[3]);
    if (lastnick > OLDEST_TS && !IsBurstOrBurstAck(sptr)) 
      cli_serv(sptr)->lag = TStime() - lastnick;
  }
  else {
    lastnick = atoi(parv[2]); 
    if (lastnick > OLDEST_TS && !IsBurstOrBurstAck(sptr))
      cli_serv(cli_user(sptr)->server)->lag = TStime() - lastnick;
  }
  /*
   * If do_nick_name() returns a null name OR if the server sent a nick
   * name and do_nick_name() changed it in some way (due to rules of nick
   * creation) then reject it. If from a server and we reject it,
   * and KILL it. -avalon 4/4/92
   */
  if (0 == do_nick_name(nick) || 0 != strcmp(nick, parv[1])) {
    send_reply(sptr, ERR_ERRONEUSNICKNAME, parv[1]);

    ++ServerStats->is_kill;
    sendto_opmask_butone(0, SNO_OLDSNO, "Bad Nick: %s From: %s %C", parv[1],
			 parv[0], cptr);
    sendcmdto_one(&me, CMD_KILL, cptr, "%s :%s (%s <- %s[%s])",
		  IsServer(sptr) ? parv[parc - 2] : parv[0], cli_name(&me), parv[1],
		  nick, cli_name(cptr));
    if (!IsServer(sptr)) {
      /*
       * bad nick _change_
       */
      sendcmdto_serv_butone(&me, CMD_KILL, 0, "%s :%s (%s <- %s!%s@%s)",
			    parv[0], cli_name(&me), cli_name(cptr), parv[0],
			    cli_user(sptr) ? cli_username(sptr) : "",
			    cli_user(sptr) ? cli_name(cli_user(sptr)->server) :
			    cli_name(cptr));
    }
    return 0;
  }
  /*
   * Check against nick name collisions.
   *
   * Put this 'if' here so that the nesting goes nicely on the screen :)
   * We check against server name list before determining if the nickname
   * is present in the nicklist (due to the way the below for loop is
   * constructed). -avalon
   */
   
  acptr = FindClient(nick);
  if (!acptr) {
    /*
     * No collisions, all clear...
     */
    return set_nick_name(cptr, sptr, nick, parc, parv);
  }
  assert(0 != acptr);

  if (IsServer(acptr)) { /* shouldn't even happen, actually */
    /*
     * We have a nickname trying to use the same name as
     * a server. Send out a nick collision KILL to remove
     * the nickname. As long as only a KILL is sent out,
     * there is no danger of the server being disconnected.
     * Ultimate way to jupiter a nick ? >;-). -avalon
     */
    sendto_opmask_butone(0, SNO_OLDSNO, "Nick collision on %C(%C <- %C)", sptr,
			 cli_from(acptr), cptr);
    ++ServerStats->is_kill;

    sendcmdto_one(&me, CMD_KILL, cptr, "%C :%s (%s <- %s)", sptr, cli_name(&me),
		  cli_name(cli_from(acptr)), cli_name(cptr));

    cli_flags(sptr) |= FLAGS_KILLED;
    /*
     * if sptr is a server it is exited here, nothing else to do
     */
    return exit_client_msg(cptr, sptr, &me,
			   "Killed (%s (%s <- %s))", 
			   feature_str(FEAT_HIS_SERVERNAME),
			   cli_name(cli_from(acptr)), cli_name(cptr));
  }

  /*
   * If acptr == sptr, then we have a client doing a nick
   * change between *equivalent* nicknames as far as server
   * is concerned (user is changing the case of his/her
   * nickname or somesuch)
   */
  if (acptr == sptr) {
    if (strcmp(cli_name(acptr), nick) != 0)
      /*
       * Allows change of case in his/her nick
       */
      return set_nick_name(cptr, sptr, nick, parc, parv);
    else
      /*
       * This is just ':old NICK old' type thing.
       * Just forget the whole thing here. There is
       * no point forwarding it to anywhere,
       * especially since servers prior to this
       * version would treat it as nick collision.
       */
      return 0;                        /* NICK Message ignored */
  }

  /*
   * Note: From this point forward it can be assumed that
   * acptr != sptr (point to different client structures).
   */
  assert(acptr != sptr);
  /*
   * If the older one is "non-person", the new entry is just
   * allowed to overwrite it. Just silently drop non-person,
   * and proceed with the nick. This should take care of the
   * "dormant nick" way of generating collisions...
   */
  if (IsUnknown(acptr) && MyConnect(acptr)) {
    ++ServerStats->is_ref;
    IPcheck_connect_fail(cli_ip(acptr));
    exit_client(cptr, acptr, &me, "Overridden by other sign on");
    return set_nick_name(cptr, sptr, nick, parc, parv);
  }
  /*
   * Decide, we really have a nick collision and deal with it
   */
  /*
   * NICK was coming from a server connection.
   * This means we have a race condition (two users signing on
   * at the same time), or two net fragments reconnecting with the same nick.
   * The latter can happen because two different users connected
   * or because one and the same user switched server during a net break.
   * If the TimeStamps are equal, we kill both (or only 'new'
   * if it was a ":server NICK new ...").
   * Otherwise we kill the youngest when user@host differ,
   * or the oldest when they are the same.
   * We treat user and ~user as different, because if it wasn't
   * a faked ~user the AUTH wouldn't have added the '~'.
   * --Run
   *
   */
  if (IsServer(sptr)) {
    /*
     * A new NICK being introduced by a neighbouring
     * server (e.g. message type ":server NICK new ..." received)
     *
     * compare IP address and username
     */
    differ =  (cli_ip(acptr).s_addr != htonl(base64toint(parv[parc - 3]))) ||
              (0 != ircd_strcmp(cli_user(acptr)->username, parv[4]));
    sendto_opmask_butone(0, SNO_OLDSNO, "Nick collision on %C (%C %Tu <- "
			 "%C %Tu (%s user@host))", acptr, cli_from(acptr),
			 cli_lastnick(acptr), cptr, lastnick,
			 differ ? "Different" : "Same");
  }
  else {
    /*
     * A NICK change has collided (e.g. message type ":old NICK new").
     *
     * compare IP address and username
     */
    differ =  (cli_ip(acptr).s_addr != cli_ip(sptr).s_addr) ||
              (0 != ircd_strcmp(cli_user(acptr)->username, cli_user(sptr)->username));              
    sendto_opmask_butone(0, SNO_OLDSNO, "Nick change collision from %C to "
			 "%C (%C %Tu <- %C %Tu)", sptr, acptr, cli_from(acptr),
			 cli_lastnick(acptr), cptr, lastnick);
  }
  /*
   * Now remove (kill) the nick on our side if it is the youngest.
   * If no timestamp was received, we ignore the incoming nick
   * (and expect a KILL for our legit nick soon ):
   * When the timestamps are equal we kill both nicks. --Run
   * acptr->from != cptr should *always* be true (?).
   *
   * This exits the client sending the NICK message
   */
  if (cli_from(acptr) != cptr) {
    if ((differ && lastnick >= cli_lastnick(acptr)) ||
	(!differ && lastnick <= cli_lastnick(acptr))) {
      if (!IsServer(sptr)) {
        ++ServerStats->is_kill;
	sendcmdto_serv_butone(&me, CMD_KILL, sptr, "%C :%s (Nick collision)",
			      sptr, cli_name(&me));
        assert(!MyConnect(sptr));

        cli_flags(sptr) |= FLAGS_KILLED;

	return exit_client_msg(cptr, sptr, &me,
			       "Killed (%s (Nick collision))",
			       feature_str(FEAT_HIS_SERVERNAME));

        /*
         * we have killed sptr off, zero out it's pointer so if it's used
         * again we'll know about it --Bleep
         */
        sptr = 0;
      }
      if (lastnick != cli_lastnick(acptr))
        return 0;                /* Ignore the NICK */
    }
    send_reply(acptr, ERR_NICKCOLLISION, nick);
  }

  ++ServerStats->is_kill;
  cli_flags(acptr) |= FLAGS_KILLED;
  /*
   * This exits the client we had before getting the NICK message
   */
  if (differ) {
    sendcmdto_serv_butone(&me, CMD_KILL, acptr, "%C :%s (older nick "
			  "overruled)", acptr, cli_name(&me));
    if (MyConnect(acptr)) {
      sendcmdto_one(acptr, CMD_QUIT, cptr, ":Killed (%s (older "
		    "nick overruled))",  feature_str(FEAT_HIS_SERVERNAME));
      sendcmdto_one(&me, CMD_KILL, acptr, "%C :%s (older nick "
		    "overruled)", acptr, feature_str(FEAT_HIS_SERVERNAME));
    }

    exit_client_msg(cptr, acptr, &me, "Killed (%s (older nick "
		    "overruled))", feature_str(FEAT_HIS_SERVERNAME));
  }
  else {
    sendcmdto_serv_butone(&me, CMD_KILL, acptr, "%C :%s (nick collision from "
			  "same user@host)", acptr, cli_name(&me));
    if (MyConnect(acptr)) {
      sendcmdto_one(acptr, CMD_QUIT, cptr, ":Killed (%s (nick "
		    "collision from same user@host))",
		    feature_str(FEAT_HIS_SERVERNAME));
      sendcmdto_one(&me, CMD_KILL, acptr, "%C :%s (older nick "
		    "overruled)", acptr, feature_str(FEAT_HIS_SERVERNAME));
    }
    exit_client_msg(cptr, acptr, &me, "Killed (%s (nick collision from "
		    "same user@host))", feature_str(FEAT_HIS_SERVERNAME));
  }
  if (lastnick == cli_lastnick(acptr))
    return 0;

  assert(0 != sptr);
  return set_nick_name(cptr, sptr, nick, parc, parv);
}
