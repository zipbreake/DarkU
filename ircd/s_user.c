/*
 * IRC - Internet Relay Chat, ircd/s_user.c (formerly ircd/s_msg.c)
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
 * $Id: s_user.c,v 1.21 2010/04/29 07:47:20 zipbreake Exp $
 */
#include "config.h"

#include "s_user.h"
#include "IPcheck.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "match.h"
#include "motd.h"
#include "msg.h"
#include "s_bdd.h"
#include "msgq.h"
#include "numeric.h"
#include "numnicks.h"
#include "parse.h"
#include "querycmds.h"
#include "random.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_serv.h" /* max_client_count */
#include "send.h"
#include "struct.h"
#include "support.h"
#include "supported.h"
#include "sys.h"
#include "userload.h"
#include "version.h"
#include "whowas.h"

#include "handlers.h" /* m_motd and m_lusers */

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

void make_virtualhost(struct Client *acptr, int mostrar);
void comprueba_privilegios(struct Client *sptr);

static int userCount = 0;

void tea(const unsigned long *const v,const unsigned long * const k,
   unsigned long *const w)
{
   register unsigned long       y=v[0]^w[0],z=v[1]^w[1],sum=0,delta=0x9E3779B9,n=32;

   while(n-->0)
      {
      y += (z << 4 ^ z >> 5) + z ^ sum + k[sum&3];
      sum += delta;
      z += (y << 4 ^ y >> 5) + y ^ sum + k[sum>>11 & 3];
      }

   w[0]=y; w[1]=z;
}


/*
 * check_dbaccess
 * Comprueba si un usuario tiene acceso a los flags 'flags' en la tabla
 * de flags de la DB
 *
 */
int check_dbaccess(struct Client *sptr, unsigned int flags)
{
	struct db_reg *reg;
	unsigned int dbflags;

	if (!IsUser(sptr))
	    return 0;

    dbflags = cli_user(sptr)->dbflags & flags;

	if (!dbflags)
		return 0;	/* No tiene ninguno de los flags */
	else if (dbflags != flags)
		return 1;	/* Tiene alguno de los flags */
	else
		return 2;	/* Tiene todos los flags */
}

/*
 * 'make_user' add's an User information block to a client
 * if it was not previously allocated.
 */
struct User *make_user(struct Client *cptr)
{
  assert(0 != cptr);

  if (!cli_user(cptr)) {
    cli_user(cptr) = (struct User*) MyMalloc(sizeof(struct User));
    assert(0 != cli_user(cptr));

    /* All variables are 0 by default */
    memset(cli_user(cptr), 0, sizeof(struct User));
#ifdef  DEBUGMODE
    ++userCount;
#endif
    cli_user(cptr)->refcnt = 1;
  }
  return cli_user(cptr);
}

/*
 * free_user
 *
 * Decrease user reference count by one and release block, if count reaches 0.
 */
void free_user(struct User* user)
{
  assert(0 != user);
  assert(0 < user->refcnt);

  if (--user->refcnt == 0) {
    if (user->away)
      MyFree(user->away);
    /*
     * sanity check
     */
    assert(0 == user->joined);
    assert(0 == user->invited);
    assert(0 == user->channel);

    MyFree(user);
#ifdef  DEBUGMODE
    --userCount;
#endif
  }
}

void user_count_memory(size_t* count_out, size_t* bytes_out)
{
  assert(0 != count_out);
  assert(0 != bytes_out);
  *count_out = userCount;
  *bytes_out = userCount * sizeof(struct User);
}


/*
 * next_client
 *
 * Local function to find the next matching client. The search
 * can be continued from the specified client entry. Normal
 * usage loop is:
 *
 * for (x = client; x = next_client(x,mask); x = x->next)
 *     HandleMatchingClient;
 *
 */
struct Client *next_client(struct Client *next, const char* ch)
{
  struct Client *tmp = next;

  if (!tmp)
    return NULL;

  next = FindClient(ch);
  next = next ? next : tmp;
  if (cli_prev(tmp) == next)
    return NULL;
  if (next != tmp)
    return next;
  for (; next; next = cli_next(next))
    if (!match(ch, cli_name(next)))
      break;
  return next;
}

/*
 * hunt_server
 *
 *    Do the basic thing in delivering the message (command)
 *    across the relays to the specific server (server) for
 *    actions.
 *
 *    Note:   The command is a format string and *MUST* be
 *            of prefixed style (e.g. ":%s COMMAND %s ...").
 *            Command can have only max 8 parameters.
 *
 *    server  parv[server] is the parameter identifying the
 *            target server. It can be a nickname, servername,
 *            or server mask (from a local user) or a server
 *            numeric (from a remote server).
 *
 *    *WARNING*
 *            parv[server] is replaced with the pointer to the
 *            real servername from the matched client (I'm lazy
 *            now --msa).
 *
 *    returns: (see #defines)
 */
int hunt_server_cmd(struct Client *from, const char *cmd, const char *tok,
                    struct Client *one, int MustBeOper, const char *pattern,
                    int server, int parc, char *parv[])
{
  struct Client *acptr;
  char *to;

  /* Assume it's me, if no server or an unregistered client */
  if (parc <= server || EmptyString((to = parv[server])) || IsUnknown(from))
    return (HUNTED_ISME);

  if (MustBeOper && !IsPrivileged(from))
  {
    send_reply(from, ERR_NOPRIVILEGES);
    return HUNTED_NOSUCH;
  }

  /* Make sure it's a server */
  if (MyUser(from)) {
    /* Make sure it's a server */
    if (!strchr(to, '*')) {
      if (0 == (acptr = FindClient(to))) {
        send_reply(from, ERR_NOSUCHSERVER, to);
        return HUNTED_NOSUCH;
      }

      if (cli_user(acptr))
        acptr = cli_user(acptr)->server;
    } else if (!(acptr = find_match_server(to))) {
      send_reply(from, ERR_NOSUCHSERVER, to);
      return (HUNTED_NOSUCH);
    }
  } else if (!(acptr = FindNServer(to)))
    return (HUNTED_NOSUCH);        /* Server broke off in the meantime */

  if (IsMe(acptr))
    return (HUNTED_ISME);

  if (MustBeOper && !IsPrivileged(from)) {
    send_reply(from, ERR_NOPRIVILEGES);
    return HUNTED_NOSUCH;
  }

  assert(!IsServer(from));

  parv[server] = (char *) acptr; /* HACK! HACK! HACK! ARGH! */

  sendcmdto_one(from, cmd, tok, acptr, pattern, parv[1], parv[2], parv[3],
                parv[4], parv[5], parv[6], parv[7], parv[8]);

  return (HUNTED_PASS);
}

int hunt_server_prio_cmd(struct Client *from, const char *cmd, const char *tok,
			 struct Client *one, int MustBeOper,
			 const char *pattern, int server, int parc,
			 char *parv[])
{
  struct Client *acptr;
  char *to;

  /* Assume it's me, if no server or an unregistered client */
  if (parc <= server || EmptyString((to = parv[server])) || IsUnknown(from))
    return (HUNTED_ISME);

  /* Make sure it's a server */
  if (MyUser(from)) {
    /* Make sure it's a server */
    if (!strchr(to, '*')) {
      if (0 == (acptr = FindClient(to))) {
        send_reply(from, ERR_NOSUCHSERVER, to);
        return HUNTED_NOSUCH;
      }

      if (cli_user(acptr))
        acptr = cli_user(acptr)->server;
    } else if (!(acptr = find_match_server(to))) {
      send_reply(from, ERR_NOSUCHSERVER, to);
      return (HUNTED_NOSUCH);
    }
  } else if (!(acptr = FindNServer(to)))
    return (HUNTED_NOSUCH);        /* Server broke off in the meantime */

  if (IsMe(acptr))
    return (HUNTED_ISME);

  if (MustBeOper && !IsPrivileged(from)) {
    send_reply(from, ERR_NOPRIVILEGES);
    return HUNTED_NOSUCH;
  }

  assert(!IsServer(from));

  parv[server] = (char *) acptr; /* HACK! HACK! HACK! ARGH! */

  sendcmdto_prio_one(from, cmd, tok, acptr, pattern, parv[1], parv[2], parv[3],
		     parv[4], parv[5], parv[6], parv[7], parv[8]);

  return (HUNTED_PASS);
}

/*
 * 'do_nick_name' ensures that the given parameter (nick) is really a proper
 * string for a nickname (note, the 'nick' may be modified in the process...)
 *
 * RETURNS the length of the final NICKNAME (0, if nickname is invalid)
 *
 * Nickname characters are in range 'A'..'}', '_', '-', '0'..'9'
 *  anything outside the above set will terminate nickname.
 * In addition, the first character cannot be '-' or a Digit.
 *
 * Note:
 *  The '~'-character should be allowed, but a change should be global,
 *  some confusion would result if only few servers allowed it...
 */
int do_nick_name(char* nick)
{
  char* ch  = nick;
  char* end = ch + NICKLEN;
  assert(0 != ch);

  if (*ch == '-' || IsDigit(*ch))        /* first character in [0..9-] */
    return 0;

  for ( ; (ch < end) && *ch; ++ch)
    if (!IsNickChar(*ch))
      break;

  *ch = '\0';

  return (ch - nick);
}

/*
 * clean_user_id
 *
 * Copy `source' to `dest', replacing all occurances of '~' and characters that
 * are not `isIrcUi' by an underscore.
 * Copies at most USERLEN - 1 characters or up till the first control character.
 * If `tilde' is true, then a tilde is prepended to `dest'.
 * Note that `dest' and `source' can point to the same area or to different
 * non-overlapping areas.
 */
static char *clean_user_id(char *dest, char *source, int tilde)
{
  char ch;
  char *d = dest;
  char *s = source;
  int rlen = USERLEN;

  ch = *s++;                        /* Store first character to copy: */
  if (tilde)
  {
    *d++ = '~';                        /* If `dest' == `source', then this overwrites `ch' */
    --rlen;
  }
  while (ch && !IsCntrl(ch) && rlen--)
  {
    char nch = *s++;        /* Store next character to copy */
    *d++ = IsUserChar(ch) ? ch : '_';        /* This possibly overwrites it */
    if (nch == '~')
      ch = '_';
    else
      ch = nch;
  }
  *d = 0;
  return dest;
}

/*
 * register_user
 *
 * This function is called when both NICK and USER messages
 * have been accepted for the client, in whatever order. Only
 * after this the USER message is propagated.
 *
 * NICK's must be propagated at once when received, although
 * it would be better to delay them too until full info is
 * available. Doing it is not so simple though, would have
 * to implement the following:
 *
 * 1) user telnets in and gives only "NICK foobar" and waits
 * 2) another user far away logs in normally with the nick
 *    "foobar" (quite legal, as this server didn't propagate it).
 * 3) now this server gets nick "foobar" from outside, but
 *    has already the same defined locally. Current server
 *    would just issue "KILL foobar" to clean out dups. But,
 *    this is not fair. It should actually request another
 *    nick from local user or kill him/her...
 */
int register_user(struct Client *cptr, struct Client *sptr,
                  const char *nick, char *username, char *hostname)
{
  struct ConfItem* aconf;
  char*            parv[3];
  char*            tmpstr;
  char*            tmpstr2;
  char             c = 0;    /* not alphanum */
  char             d = 'a';  /* not a digit */
  short            upper = 0;
  short            lower = 0;
  short            pos = 0;
  short            leadcaps = 0;
  short            other = 0;
  short            digits = 0;
  short            badid = 0;
  short            digitgroups = 0;
  struct User*     user = cli_user(sptr);
  char             ip_base64[8];
  struct db_reg*   reg;
  int              type_kill;

  user->last = CurrentTime;
  parv[0] = cli_name(sptr);
  parv[1] = parv[2] = NULL;


  if (MyConnect(sptr))
  {
    static time_t last_too_many1;
    static time_t last_too_many2;

    assert(cptr == sptr);

	cli_negociacion(cptr) = 0;	/* La negociación solo existe servidor <=> servidor */

    switch (conf_check_client(sptr))
    {
      case ACR_OK:
        break;
      case ACR_NO_AUTHORIZATION:
        sendto_opmask_butone(0, SNO_UNAUTH, "Unauthorized connection from %s.",
                             get_client_name(sptr, HIDE_IP));
        ++ServerStats->is_ref;
        return exit_client(cptr, sptr, &me,
                           "No Authorization - use another server");
      case ACR_TOO_MANY_IN_CLASS:
        if (CurrentTime - last_too_many1 >= (time_t) 60)
        {
          last_too_many1 = CurrentTime;
          sendto_opmask_butone(0, SNO_TOOMANY, "Too many connections in "
                               "class %i for %s.", get_client_class(sptr),
                               get_client_name(sptr, SHOW_IP));
        }
        ++ServerStats->is_ref;
        IPcheck_connect_fail(cli_ip(sptr));
        return exit_client(cptr, sptr, &me,
                           "Sorry, your connection class is full - try "
                           "again later or try another server");
      case ACR_TOO_MANY_FROM_IP:
        if (CurrentTime - last_too_many2 >= (time_t) 60)
        {
          last_too_many2 = CurrentTime;
          sendto_opmask_butone(0, SNO_TOOMANY, "Too many connections from "
                               "same IP for %s.",
                               get_client_name(sptr, SHOW_IP));
        }
        ++ServerStats->is_ref;
        return exit_client(cptr, sptr, &me,
                           "Too many connections from your host");
      case ACR_ALREADY_AUTHORIZED:
        /* Can this ever happen? */
      case ACR_BAD_SOCKET:
        ++ServerStats->is_ref;
        IPcheck_connect_fail(cli_ip(sptr));
        return exit_client(cptr, sptr, &me, "Unknown error -- Try again");
    }
    if (feature_bool(FEAT_WEBCHAT_CONFIG))
        ircd_strncpy(user->realhost, hostname, HOSTLEN);
    else
        ircd_strncpy(user->realhost, cli_sockhost(sptr), HOSTLEN);
    aconf = cli_confs(sptr)->value.aconf;

    // Debemos desactivar el ident
    cli_flags(sptr) &= ~FLAGS_DOID;

    clean_user_id(user->username,
        (cli_flags(sptr) & FLAGS_GOTID) ? cli_username(sptr) : username,
        (cli_flags(sptr) & FLAGS_DOID) && !(cli_flags(sptr) & FLAGS_GOTID));

    if ((user->username[0] == '\0')
        || ((user->username[0] == '~') && (user->username[1] == '\000')))
      return exit_client(cptr, sptr, &me, "USER: Bogus userid.");

    if (!EmptyString(aconf->passwd)
        && !(IsDigit(*aconf->passwd) && !aconf->passwd[1])
        && strcmp(cli_passwd(sptr), aconf->passwd))
    {
      ServerStats->is_ref++;
      IPcheck_connect_fail(cli_ip(sptr));
      send_reply(sptr, ERR_PASSWDMISMATCH);
      return exit_client(cptr, sptr, &me, "Bad Password");
    }
//    memset(cli_passwd(sptr), 0, sizeof(cli_passwd(sptr)));
    /*
     * following block for the benefit of time-dependent K:-lines
     */
    if ((type_kill = find_kill(sptr))) {
      ServerStats->is_ref++;
      IPcheck_connect_fail(cli_ip(sptr));
      return exit_client(cptr, sptr, &me, type_kill == -2 ? "G-lined" : "K-lined");
    }
    /*
     * Check for mixed case usernames, meaning probably hacked.  Jon2 3-94
     * Summary of rules now implemented in this patch:         Ensor 11-94
     * In a mixed-case name, if first char is upper, one more upper may
     * appear anywhere.  (A mixed-case name *must* have an upper first
     * char, and may have one other upper.)
     * A third upper may appear if all 3 appear at the beginning of the
     * name, separated only by "others" (-/_/.).
     * A single group of digits is allowed anywhere.
     * Two groups of digits are allowed if at least one of the groups is
     * at the beginning or the end.
     * Only one '-', '_', or '.' is allowed (or two, if not consecutive).
     * But not as the first or last char.
     * No other special characters are allowed.
     * Name must contain at least one letter.
     */
#ifdef compilar_ident
    tmpstr2 = tmpstr = (username[0] == '~' ? &username[1] : username);
    while (*tmpstr && !badid)
    {
      pos++;
      c = *tmpstr;
      tmpstr++;
      if (IsLower(c))
      {
        lower++;
      }
      else if (IsUpper(c))
      {
        upper++;
        if ((leadcaps || pos == 1) && !lower && !digits)
          leadcaps++;
      }
      else if (IsDigit(c))
      {
        digits++;
        if (pos == 1 || !IsDigit(d))
        {
          digitgroups++;
          if (digitgroups > 2)
            badid = 1;
        }
      }
      else if (c == '-' || c == '_' || c == '.')
      {
        other++;
        if (pos == 1)
          badid = 1;
        else if (d == '-' || d == '_' || d == '.' || other > 2)
          badid = 1;
      }
      else
        badid = 1;
      d = c;
    }
    if (!badid)
    {


/*      if (lower && upper && (!leadcaps || leadcaps > 3 ||
          (upper > 2 && upper > leadcaps)))
        badid = 1;
      else */if (digitgroups == 2 && !(IsDigit(tmpstr2[0]) || IsDigit(c)))
        badid = 1;
      else if ((!lower && !upper) || !IsAlnum(c))
        badid = 1;
    }
    if (badid && (!(cli_flags(sptr) & FLAGS_GOTID) ||
        strcmp(cli_username(sptr), username) != 0))
    {
      ServerStats->is_ref++;

      send_reply(cptr, SND_EXPLICIT | ERR_INVALIDUSERNAME,
                 ":Your username is invalid.");
      send_reply(cptr, SND_EXPLICIT | ERR_INVALIDUSERNAME,
                 ":Connect with your real username, in lowercase.");
      send_reply(cptr, SND_EXPLICIT | ERR_INVALIDUSERNAME,
                 ":If your mail address were foo@bar.com, your username "
                 "would be foo.");
      return exit_client(cptr, sptr, &me, "USER: Bad username");
    }
#endif
    Count_unknownbecomesclient(sptr, UserStats);
  }
  else {
    ircd_strncpy(user->username, username, USERLEN);
    Count_newremoteclient(UserStats, user->server);
  }
  SetUser(sptr);

  if (IsInvisible(sptr))
    ++UserStats.inv_clients;
  if (IsOper(sptr))
    ++UserStats.opers;

  /* Si el IRCd es exclusivo de WebChats todos tienen +W */
  if (feature_bool(FEAT_WEBCHAT_CONFIG))
      cli_rhflags(sptr) |= RHFLAGS_WEBCHAT;

  if (MyConnect(sptr)) {
    cli_handler(sptr) = CLIENT_HANDLER;
    release_dns_reply(sptr);

    send_reply(sptr, RPL_WELCOME, nick);
    /*
     * This is a duplicate of the NOTICE but see below...
     */
    
    /** A partir de RH.02.91, el nombre del servidor real
     ** no se muestra en RPL_YOURHOST y RPL_MYINFO, para
     ** mantener la confidencialidad que deseamos.
     **
     ** Para ello, hemos creado la F:Line
     ** 'RH_PSEUDO_SERVERNAME', que debe contener el
     ** pseudo-nombre del servidor. No usamos la
     ** actual 'HIS_SERVERNAME', ya que el uso de '*'
     ** es frecuente, y por lo tanto puede dar problemas
     ** de compatibilidad con clientes.
     **
     ** -- mount@redhispana.org - 25/04/04
     **/
    send_reply(sptr, RPL_YOURHOST, feature_str(FEAT_RH_PSEUDO_SERVERNAME), version);
    send_reply(sptr, RPL_CREATED, creation);
    send_reply(sptr, RPL_MYINFO, feature_str(FEAT_RH_PSEUDO_SERVERNAME), version);
    
    send_supported(sptr);
    m_lusers(sptr, sptr, 1, parv);
	m_users(sptr, sptr, 1, parv);
    update_load();
    motd_signon(sptr);
/*      nextping = CurrentTime; */
    if (cli_snomask(sptr) & SNO_NOISY)
      set_snomask(sptr, cli_snomask(sptr) & SNO_NOISY, SNO_ADD);
    if (feature_bool(FEAT_CONNEXIT_NOTICES))
      sendto_opmask_butone(0, SNO_CONNEXIT,
			   "Client connecting: %s (%s@%s) [%s] {%d}",
			   cli_name(sptr), user->username, get_realhost(sptr),
			   cli_sock_ip(sptr), get_client_class(sptr));
    IPcheck_connect_succeeded(sptr);
  }
  else
    /* if (IsServer(cptr)) */
  {
    struct Client *acptr;

    acptr = user->server;
    if (cli_from(acptr) != cli_from(sptr))
    {
      sendcmdto_one(&me, CMD_KILL, cptr, "%C :%s (%s != %s[%s])",
                    sptr, cli_name(&me), cli_name(user->server), cli_name(cli_from(acptr)),
                    cli_sockhost(cli_from(acptr)));
      cli_flags(sptr) |= FLAGS_KILLED;
      return exit_client(cptr, sptr, &me, "NICK server wrong direction");
    }
    else
      cli_flags(sptr) |= (cli_flags(acptr) & FLAGS_TS8);

    /*
     * Check to see if this user is being propogated
     * as part of a net.burst, or is using protocol 9.
     * FIXME: This can be speeded up - its stupid to check it for
     * every NICK message in a burst again  --Run.
     */
    for (acptr = user->server; acptr != &me; acptr = cli_serv(acptr)->up) {
      if (IsBurst(acptr) || Protocol(acptr) < 10)
        break;
    }
    if (!IPcheck_remote_connect(sptr, (acptr != &me))) {
      /*
       * We ran out of bits to count this
       */
      sendcmdto_one(&me, CMD_KILL, sptr, "%C :%s (Too many connections from "
		    "your host -- Ghost)", sptr, cli_name(&me));
      return exit_client(cptr, sptr, &me, "Too many connections from your"
			 " host -- throttled");
    }
  }
  tmpstr = umode_str(sptr);
  sendcmdto_serv_butone(user->server, CMD_NICK, cptr,
			"%s %d %Tu %s %s %s%s%s%s %s%s :%s",
			nick, cli_hopcount(sptr) + 1, cli_lastnick(sptr),
			user->username, user->realhost,
			*tmpstr ? "+" : "", tmpstr, *tmpstr ? " " : "",
			inttobase64(ip_base64, ntohl(cli_ip(sptr).s_addr), 6),
			NumNick(sptr), cli_info(sptr));
  
  /* Send umode to client */
  if (MyUser(sptr))
  {
    /* make_virtualhost(sptr, 0); */
    send_umode(cptr, sptr, 0, 0, ALL_UMODES, RHFLAGS);
    if (cli_snomask(sptr) != SNO_DEFAULT && (cli_flags(sptr) & FLAGS_SERVNOTICE))
      send_reply(sptr, RPL_SNOMASK, cli_snomask(sptr), cli_snomask(sptr));

    /* AUTOJOIN desde lines F, localmente */
    if (feature_str(FEAT_AUTOJOIN)) {
	char* join[2];
	char  chan[CHANNELLEN-1];

        ircd_strncpy(chan, feature_str(FEAT_AUTOJOIN), CHANNELLEN-1);
        join[0] = cli_name(sptr);
        join[1] = chan;
        m_join(sptr, sptr, 2, join);
    }
  }

  return 0;
}


static const struct UserMode {
  unsigned int flag;
  char         c;
} userModeList[] = {
  { FLAGS_OPER,        'o' },
  { FLAGS_LOCOP,       'O' },
  { FLAGS_INVISIBLE,   'i' },
  { FLAGS_WALLOP,      'w' },
  { FLAGS_SERVNOTICE,  's' },
  { FLAGS_DEAF,        'd' },
  { FLAGS_CHSERV,      'k' },
  { FLAGS_DEBUG,       'g' },
  { FLAGS_HIDDENHOST,  'x' }
};

static const struct UserMode RHuserModeList[] = {
	{ RHFLAGS_REGNICK,	'r' },
	{ RHFLAGS_SUSPENDED,    'S' },
	{ RHFLAGS_VIEWIP,	'X' },
	{ RHFLAGS_INVISIBLE,	'I' },
	{ RHFLAGS_LOCADMIN,	'A' },
	{ RHFLAGS_HELPOP,	'h' },
	{ RHFLAGS_COADM,	'c' },
	{ RHFLAGS_ADM,		'a' },
	{ RHFLAGS_MODERA,	'm' },
	{ RHFLAGS_ONLYREG,	'R' },
	{ RHFLAGS_USERBOT,	'b' },
	{ RHFLAGS_BOT,		'B' },
	{ RHFLAGS_WEBCHAT,      'W' },
	{ RHFLAGS_SECURE,       'z' }
};

#define USERMODELIST_SIZE sizeof(userModeList) / sizeof(struct UserMode)
#define RHUSERMODELIST_SIZE sizeof(RHuserModeList) / sizeof(struct UserMode)

/*
 * XXX - find a way to get rid of this
 */
static char umodeBuf[BUFSIZE];

int set_nick_name(struct Client* cptr, struct Client* sptr,
                  const char* nick, int parc, char* parv[])
{
  unsigned long fold = cli_flags(sptr), frhold = cli_rhflags(sptr);
  if (IsServer(sptr)) {
    int   i;
    const char* account = 0;
    const char* p;

    /*
     * A server introducing a new client, change source
     */
    struct Client* new_client = make_client(cptr, STAT_UNKNOWN);
    assert(0 != new_client);

    cli_hopcount(new_client) = atoi(parv[2]);
    cli_lastnick(new_client) = atoi(parv[3]);
    if (Protocol(cptr) > 9 && parc > 7 && *parv[6] == '+') {

		for (p = parv[6] + 1; *p; p++) {
			for (i = 0; i < USERMODELIST_SIZE; ++i) {
				if (userModeList[i].c == *p) {
					cli_flags(new_client) |= userModeList[i].flag;
					if (userModeList[i].flag & FLAGS_ACCOUNT)
						account = parv[7];
					break;
				}
			}
			for (i = 0; i < RHUSERMODELIST_SIZE; ++i) {
				if (RHuserModeList[i].c == *p) {
					cli_rhflags(new_client) |= RHuserModeList[i].flag;
					break;
				}
			}
		}

    }
    client_set_privs(new_client); /* set privs on user */
    /*
     * Set new nick name.
     */
    strcpy(cli_name(new_client), nick);
    cli_user(new_client) = make_user(new_client);
    cli_user(new_client)->server = sptr;
    SetRemoteNumNick(new_client, parv[parc - 2]);
    /*
     * IP# of remote client
     */
    cli_ip(new_client).s_addr = htonl(base64toint(parv[parc - 3]));

    add_client_to_list(new_client);
    hAddClient(new_client);

    cli_serv(sptr)->ghost = 0;        /* :server NICK means end of net.burst */
    ircd_strncpy(cli_username(new_client), parv[4], USERLEN);
    ircd_strncpy(cli_user(new_client)->realhost, parv[5], HOSTLEN);
    ircd_strncpy(cli_info(new_client), parv[parc - 1], REALLEN);

    if (account)
      ircd_strncpy(cli_user(new_client)->account, account, ACCOUNTLEN);
    if (HasHiddenHost(new_client))
	make_virtualhost(new_client, 0);

    return register_user(cptr, new_client, cli_name(new_client), parv[4], parv[5]);
  }
  else if ((cli_name(sptr))[0]) {
    struct db_reg *reg;
    char *botname;

	/*
     * Client changing its nick
     *
     * If the client belongs to me, then check to see
     * if client is on any channels where it is currently
     * banned.  If so, do not allow the nick change to occur.
     */
    if (MyUser(sptr)) {
      const char* channel_name;
      struct Membership *member;
      if ((channel_name = find_no_nickchange_channel(sptr))) {
        send_reply(cptr, ERR_BANNICKCHANGE, channel_name);
		return 5;
      }
      /*
       * Refuse nick change if the last nick change was less
       * then 30 seconds ago. This is intended to get rid of
       * clone bots doing NICK FLOOD. -SeKs
       * If someone didn't change their nick for more then 60 seconds
       * however, allow to do two nick changes immedately after another
       * before limiting the nick flood. -Run
       */
      if (!(cli_rhflags(sptr) & RHFLAGS_RENAMED)) {
	    if (CurrentTime < cli_nextnick(cptr) && !(cli_flags(cptr) & FLAGS_CHSERV)) {
		   cli_nextnick(cptr) += 2;
		send_reply(cptr, ERR_NICKTOOFAST, nick,
                   cli_nextnick(cptr) - CurrentTime);
        /* Send error message */
        // sendcmdto_one(cptr, CMD_NICK, cptr, "%s", cli_name(cptr));
        /* bounce NICK to user */
        return 5;                /* ignore nick change! */
      }
      else {
        /* Limit total to 1 change per NICK_DELAY seconds: */
        cli_nextnick(cptr) += NICK_DELAY;
        /* However allow _maximal_ 1 extra consecutive nick change: */
        if (cli_nextnick(cptr) < CurrentTime)
          cli_nextnick(cptr) = CurrentTime;
      }
	  }
	  
	  if ((reg = db_buscar_registro(BDD_BOTS, BDD_BOTS_CHANSERV)) && (reg->valor))
	     botname = reg->valor;
      else
         botname = cli_name(&me);
	  
      /* Invalidate all bans against the user so we check them again */
      for (member = (cli_user(cptr))->channel; member;
	   member = member->next_channel)
	   {
	   	ClearBanValid(member);

	 /* Si es fundador eliminamos el fundador */
         if (MyUser(member->user) && (member->channel->founder))
	 {
           member->channel->founder = NULL;
         }
       }
    }
    /*
     * Also set 'lastnick' to current time, if changed.
     */
	if (!(cli_rhflags(sptr) & RHFLAGS_RENAMED))
		if (0 != ircd_strcmp(parv[0], nick))
			cli_lastnick(sptr) = (sptr == cptr) ? TStime() : atoi(parv[2]);

    /*
     * Client just changing his/her nick. If he/she is
     * on a channel, send note of change to all clients
     * on that channel. Propagate notice to other servers.
     */
    if (IsUser(sptr)) {
      sendcmdto_common_channels_butone(sptr, CMD_NICK, NULL, ":%s", nick);
      add_history(sptr, 1);
      sendcmdto_serv_butone(sptr, CMD_NICK, cptr, "%s %Tu", nick,
                            cli_lastnick(sptr));
    }
    else
      sendcmdto_one(sptr, CMD_NICK, sptr, ":%s", nick);

    if ((cli_name(sptr))[0])
      hRemClient(sptr);
    strcpy(cli_name(sptr), nick);
    hAddClient(sptr);
	cli_rhflags(sptr) &= ~RHFLAGS_RENAMED;

    if (cli_user(sptr))
        make_virtualhost(sptr, 1);
  }
  else {
    /* Local client setting NICK the first time */

    strcpy(cli_name(sptr), nick);
    if (!cli_user(sptr)) {
      cli_user(sptr) = make_user(sptr);
      cli_user(sptr)->server = &me;
    }
    SetLocalNumNick(sptr);
    hAddClient(sptr);

    /*
     * If the client hasn't gotten a cookie-ping yet,
     * choose a cookie and send it. -record!jegelhof@cloud9.net
     */
    if (!cli_cookie(sptr)) {
      do {
        cli_cookie(sptr) = (ircrandom() & 0x7fffffff);
      } while (!cli_cookie(sptr));
      sendrawto_one(cptr, MSG_PING " :%u", cli_cookie(sptr));
    }
    else if (*(cli_user(sptr))->realhost && cli_cookie(sptr) == COOKIE_VERIFIED) {
      /*
       * USER and PONG already received, now we have NICK.
       * register_user may reject the client and call exit_client
       * for it - must test this and exit m_nick too !
       */
      cli_lastnick(sptr) = TStime();        /* Always local client */
      if (register_user(cptr, sptr, nick, cli_user(sptr)->username, cli_user(sptr)->realhost) == CPTR_KILLED)
        return CPTR_KILLED;
    }
    if (cli_user(sptr))
        make_virtualhost(sptr, 0);
  }
  return 0;
}

static unsigned char hash_target(unsigned int target)
{
  return (unsigned char) (target >> 16) ^ (target >> 8);
}

/*
 * add_target
 *
 * sptr must be a local client!
 *
 * Cannonifies target for client `sptr'.
 */
void add_target(struct Client *sptr, void *target)
{
  /* Ok, this shouldn't work esp on alpha
  */
  unsigned char  hash = hash_target((unsigned long) target);
  unsigned char* targets;
  int            i;
  assert(0 != sptr);
  assert(cli_local(sptr));

  targets = cli_targets(sptr);
  /* 
   * Already in table?
   */
  for (i = 0; i < MAXTARGETS; ++i) {
    if (targets[i] == hash)
      return;
  }
  /*
   * New target
   */
  memmove(&targets[RESERVEDTARGETS + 1],
          &targets[RESERVEDTARGETS], MAXTARGETS - RESERVEDTARGETS - 1);
  targets[RESERVEDTARGETS] = hash;
}

/*
 * check_target_limit
 *
 * sptr must be a local client !
 *
 * Returns 'true' (1) when too many targets are addressed.
 * Returns 'false' (0) when it's ok to send to this target.
 */
int check_target_limit(struct Client *sptr, void *target, const char *name,
    int created)
{
  unsigned char hash = hash_target((unsigned long) target);
  int            i;
  unsigned char* targets;

  assert(0 != sptr);
  assert(cli_local(sptr));
  targets = cli_targets(sptr);
  /* If user is invited to channel, give him/her a free target */
  if (IsChannelName(name) && IsInvited(sptr, target))
    return 0;
  /*
   * Same target as last time?
   */
  if (targets[0] == hash)
    return 0;
  for (i = 1; i < MAXTARGETS; ++i) {
    if (targets[i] == hash) {
      memmove(&targets[1], &targets[0], i);
      targets[0] = hash;
      return 0;
    }
  }
  /*
   * New target
   */
  if (!created) {
    if (CurrentTime < cli_nexttarget(sptr)) {
      if (cli_nexttarget(sptr) - CurrentTime < TARGET_DELAY + 8) {
        /*
         * No server flooding
         */
		  if (!(cli_flags(sptr) & FLAGS_CHSERV)) {
			cli_nexttarget(sptr) += 2;
			send_reply(sptr, ERR_TARGETTOOFAST, name,
				       cli_nexttarget(sptr) - CurrentTime);
		  }
      }
      return 1;
    }
    else {
      cli_nexttarget(sptr) += TARGET_DELAY;
      if (cli_nexttarget(sptr) < CurrentTime - (TARGET_DELAY * (MAXTARGETS - 1)))
        cli_nexttarget(sptr) = CurrentTime - (TARGET_DELAY * (MAXTARGETS - 1));
    }
  }
  memmove(&targets[1], &targets[0], MAXTARGETS - 1);
  targets[0] = hash;
  return 0;
}

/*
 * whisper - called from m_cnotice and m_cprivmsg.
 *
 * parv[0] = sender prefix
 * parv[1] = nick
 * parv[2] = #channel
 * parv[3] = Private message text
 *
 * Added 971023 by Run.
 * Reason: Allows channel operators to sent an arbitrary number of private
 *   messages to users on their channel, avoiding the max.targets limit.
 *   Building this into m_private would use too much cpu because we'd have
 *   to a cross channel lookup for every private message!
 * Note that we can't allow non-chan ops to use this command, it would be
 *   abused by mass advertisers.
 *
 */
int whisper(struct Client* source, const char* nick, const char* channel,
            const char* text, int is_notice)
{
  struct Client*     dest;
  struct Channel*    chptr;
  struct Membership* membership;

  assert(0 != source);
  assert(0 != nick);
  assert(0 != channel);
  assert(MyUser(source));

  if (!(dest = FindUser(nick))) {
    return send_reply(source, ERR_NOSUCHNICK, nick);
  }
  if (!(chptr = FindChannel(channel))) {
    return send_reply(source, ERR_NOSUCHCHANNEL, channel);
  }
  /*
   * compare both users channel lists, instead of the channels user list
   * since the link is the same, this should be a little faster for channels
   * with a lot of users
   */
  for (membership = cli_user(source)->channel; membership; membership = membership->next_channel) {
    if (chptr == membership->channel)
      break;
  }
  if (0 == membership) {
    return send_reply(source, ERR_NOTONCHANNEL, chptr->chname);
  }
  if (!IsVoicedOrOpped(membership)) {
    return send_reply(source, ERR_VOICENEEDED, chptr->chname);
  }
  /*
   * lookup channel in destination
   */
  assert(0 != cli_user(dest));
  for (membership = cli_user(dest)->channel; membership; membership = membership->next_channel) {
    if (chptr == membership->channel)
      break;
  }
  if (0 == membership || IsZombie(membership)) {
    return send_reply(source, ERR_USERNOTINCHANNEL, cli_name(dest), chptr->chname);
  }
  if (is_silenced(source, dest))
    return 0;
          
  if (cli_user(dest)->away)
    send_reply(source, RPL_AWAY, cli_name(dest), cli_user(dest)->away);
  if (is_notice)
    sendcmdto_one(source, CMD_NOTICE, dest, "%C :%s", dest, text);
  else
    sendcmdto_one(source, CMD_PRIVATE, dest, "%C :%s", dest, text);
  return 0;
}


/*
 * added Sat Jul 25 07:30:42 EST 1992
 */
void send_umode_out(struct Client *cptr, struct Client *sptr, int old, int oldrh,
		    int prop)
{
  int i;
  struct Client *acptr;

  send_umode(NULL, sptr, old, oldrh, SEND_UMODES & ~(prop ? 0 : FLAGS_OPER), RHFLAGS);

  for (i = HighestFd; i >= 0; i--) {
    if ((acptr = LocalClientArray[i]) && IsServer(acptr) &&
        (acptr != cptr) && (acptr != sptr) && *umodeBuf)
      sendcmdto_one(sptr, CMD_MODE, acptr, "%s :%s", cli_name(sptr), umodeBuf);
  }
  if (cptr && MyUser(cptr))
    send_umode(cptr, sptr, old, oldrh, ALL_UMODES, RHFLAGS);
}


/*
 * send_user_info - send user info userip/userhost
 * NOTE: formatter must put info into buffer and return a pointer to the end of
 * the data it put in the buffer.
 */
void send_user_info(struct Client* sptr, char* names, int rpl, InfoFormatter fmt)
{
  char*          name;
  char*          p = 0;
  int            arg_count = 0;
  int            users_found = 0;
  struct Client* acptr;
  struct MsgBuf* mb;

  assert(0 != sptr);
  assert(0 != names);
  assert(0 != fmt);

  mb = msgq_make(sptr, rpl_str(rpl), cli_name(&me), cli_name(sptr));

  for (name = ircd_strtok(&p, names, " "); name; name = ircd_strtok(&p, 0, " ")) {
    if ((acptr = FindUser(name))) {
      if (users_found++)
	msgq_append(0, mb, " ");
      (*fmt)(acptr, sptr, mb);
    }
    if (5 == ++arg_count)
      break;
  }
  send_buffer(sptr, mb, 0);
  msgq_clean(mb);
}

/*
 * hide_hostmask()
 *
 * If, after setting the flags, the user has both HiddenHost and Account
 * set, its hostmask is changed.
 */
#define FLAGS_HOST_HIDDEN	(FLAGS_ACCOUNT|FLAGS_HIDDENHOST)
int hide_hostmask(struct Client *cptr, unsigned int flags)
{
  struct Membership *chan;
  int newflags;

  if (MyConnect(cptr) && !feature_bool(FEAT_HOST_HIDING))
    flags &= ~FLAGS_HIDDENHOST;
    
  newflags = cli_flags(cptr) | flags;
  if ((newflags & FLAGS_HOST_HIDDEN) != FLAGS_HOST_HIDDEN) {
    /* The user doesn't have both flags, don't change the hostmask */
    cli_flags(cptr) |= flags;
    return 0;
  }

  sendcmdto_common_channels_butone(cptr, CMD_QUIT, cptr, ":Registered");
  ircd_snprintf(0, cli_user(cptr)->realhost, HOSTLEN, "%s.%s",
    cli_user(cptr)->account, feature_str(FEAT_HIDDEN_HOST));
  cli_flags(cptr) |= flags;

  /*
   * Go through all channels the client was on, rejoin him
   * and set the modes, if any
   */
  for (chan = cli_user(cptr)->channel; chan; chan = chan->next_channel) {
    sendcmdto_channel_butserv_butone(cptr, CMD_JOIN, chan->channel, cptr,
      "%H", chan->channel);
    if (IsChanOp(chan) && HasVoice(chan)) {
      sendcmdto_channel_butserv_butone(&me, CMD_MODE, chan->channel, cptr,
        "%H +ov %C %C", chan->channel, cptr, cptr);
    } else if (IsChanOp(chan) || HasVoice(chan)) {
      sendcmdto_channel_butserv_butone(&me, CMD_MODE, chan->channel, cptr,
        "%H +%c %C", chan->channel, IsChanOp(chan) ? 'o' : 'v', cptr);
    }
  }
  return 0;
}


void comprueba_privilegios(struct Client *sptr)
{
  struct db_reg *reg;
  unsigned int allowed_flags;
	
  if (cli_user(sptr) == NULL)
  {
    return;
  }
 
  allowed_flags = cli_user(sptr)->dbflags;

  if (IsSuspended(sptr) || !(db_buscar_registro(BDD_NICKS, cli_name(sptr))))
  {
    ClearRegnick(sptr);
  }
	
  if (!IsRegnick(sptr))
  {
    allowed_flags = 0;
  }

  if (!allowed_flags)
  {
    ClearAdmin(sptr);
    ClearCoadmin(sptr);
    ClearHelpOp(sptr);
    ClearLocAdmin(sptr);
    ClearModera(sptr);
    ClearUserbot(sptr);
    ClearBot(sptr);
    ClearViewip(sptr);
  }
	
  while (!!(allowed_flags))
  {
    if (IsAdmin(sptr))
    {
      if (!(allowed_flags & OPER_ALLOWED_a))
      {
        ClearAdmin(sptr);
      }
      else
      {
        ClearCoadmin(sptr);
        ClearHelpOp(sptr);
        ClearLocAdmin(sptr);
        ClearModera(sptr);
        break;
      }
    }

    if (IsCoadmin(sptr))
    {
      if (!(allowed_flags & OPER_ALLOWED_c))
      {
        ClearCoadmin(sptr);
      }
      else
      {
        ClearHelpOp(sptr);
        ClearModera(sptr);
        ClearLocAdmin(sptr);
        break;
      }
    }

    if (IsLocAdmin(sptr))
    {
      if (!(allowed_flags & OPER_ALLOWED_A))
      {
        ClearLocAdmin(sptr);
      }
      else
      {
        ClearHelpOp(sptr);
        ClearModera(sptr);
        break;
      }
    }

    if (IsHelpOp(sptr))
    {
      if (!(allowed_flags & OPER_ALLOWED_h))
      {
        ClearHelpOp(sptr);
      }
      else
      {
        ClearModera(sptr);
        break;
      }
    }

    if (IsModera(sptr) && (!(allowed_flags & OPER_ALLOWED_m)))
    {
      ClearModera(sptr);
    }
    break;
  }

  if (allowed_flags)
  {
    do
    {
      if (IsBot(sptr))
      {
        if (!(allowed_flags & OPER_ALLOWED_B))
        {
          ClearBot(sptr);
        }
        else
        {
          ClearUserbot(sptr);
          break;
        }
      }
	
      if (IsUserbot(sptr) && !(allowed_flags & OPER_ALLOWED_b))
      {
        ClearUserbot(sptr);
      }
    } while (0);

    if (IsViewip(sptr) && !(allowed_flags & OPER_ALLOWED_X))
    {
      ClearViewip(sptr);
    }
  }

  if (IsOnlyreg(sptr) && !IsRegnick(sptr))
  {
    ClearOnlyreg(sptr);
  }

  /* El +k solo debería estar accesible por BDD y a IRC operators */
  if (cli_flags(sptr) & FLAGS_CHSERV)
  {
    if (!IsOper(sptr) && !(allowed_flags & OPER_ALLOWED_k))
    {
      cli_flags(sptr) &= ~FLAGS_CHSERV;
    }
  }
}

/*
 * set_user_mode() added 15/10/91 By Darren Reed.
 *
 * parv[0] - sender
 * parv[1] - username to change mode for
 * parv[2] - modes to change
 */
int set_user_mode(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  char** p;
  char*  m;
  struct Client *acptr;
  int what;
  int i;
  int setflags, rhsetflags;
  unsigned int tmpmask = 0;
  int snomask_given = 0;
  char buf[BUFSIZE];
  int prop = 0;
  int do_host_hiding = 0;

  what = MODE_ADD;

  if (parc < 2)
    return need_more_params(sptr, "MODE");

  if (!(acptr = FindUser(parv[1])))
  {
    if (MyConnect(sptr))
      send_reply(sptr, ERR_NOSUCHCHANNEL, parv[1]);
    return 0;
  }

  if (IsServer(sptr) || sptr != acptr)
  {
    if (IsServer(cptr))
      sendwallto_group_butone(&me, WALL_WALLOPS, 0, 
	  		    "MODE for User %s from %s!%s", parv[1],
                            cli_name(cptr), cli_name(sptr));
    else
      send_reply(sptr, ERR_USERSDONTMATCH);
    return 0;
  }

  if (parc < 3)
  {
    m = buf;
    *m++ = '+';
    for (i = 0; i < USERMODELIST_SIZE; ++i) {
      if ((userModeList[i].flag & cli_flags(sptr)))
        *m++ = userModeList[i].c;
    }
	for (i = 0; i < RHUSERMODELIST_SIZE; ++i) {
		if ((RHuserModeList[i].flag & cli_rhflags(sptr)))
			*m++ = RHuserModeList[i].c;
	}
    *m = '\0';
    send_reply(sptr, RPL_UMODEIS, buf);
    if ((cli_flags(sptr) & FLAGS_SERVNOTICE) && MyConnect(sptr)
        && cli_snomask(sptr) !=
        (unsigned int)(IsOper(sptr) ? SNO_OPERDEFAULT : SNO_DEFAULT))
      send_reply(sptr, RPL_SNOMASK, cli_snomask(sptr), cli_snomask(sptr));
    return 0;
  }

  /*
   * find flags already set for user
   * why not just copy them?
   */
  setflags = cli_flags(sptr);
  rhsetflags = cli_rhflags(sptr);

  if (MyConnect(sptr))
    tmpmask = cli_snomask(sptr);

  /*
   * parse mode change string(s)
   */
  for (p = &parv[2]; *p; p++) {       /* p is changed in loop too */
    for (m = *p; *m; m++) {
      switch (*m) {
      case '+':
        what = MODE_ADD;
        break;
      case '-':
        what = MODE_DEL;
        break;

		/* Server notices */
      case 's':
        if (*(p + 1) && is_snomask(*(p + 1))) {
          snomask_given = 1;
          tmpmask = umode_make_snomask(tmpmask, *++p, what);
          tmpmask &= (IsAnOper(sptr) ? SNO_ALL : SNO_USER);
        }
        else
          tmpmask = (what == MODE_ADD) ?
              (IsAnOper(sptr) ? SNO_OPERDEFAULT : SNO_DEFAULT) : 0;
        if (tmpmask)
	  SetServNotice(sptr);
        else
	  ClearServNotice(sptr);
        break;

		/* Wallops */
      case 'w':
        if (what == MODE_ADD)
          SetWallops(sptr);
        else
          ClearWallops(sptr);
        break;

		/* IRC Operator */
      case 'o':
		  if (what == MODE_ADD) {
			if (MyUser(sptr))
				break;
			cli_flags(sptr) |= FLAGS_OPER;
		  } else {
          cli_flags(sptr) &= ~(FLAGS_OPER | FLAGS_LOCOP);
          if (MyConnect(sptr)) {
            tmpmask = cli_snomask(sptr) & ~SNO_OPER;
            cli_handler(sptr) = CLIENT_HANDLER;
          }
        }
        break;

		/* Local IRC Operator */
      case 'O':
        if (what == MODE_ADD)
          break;
        else { 
          cli_flags(sptr) &= ~(FLAGS_OPER | FLAGS_LOCOP);
          if (MyConnect(sptr)) {
            tmpmask = cli_snomask(sptr) & ~SNO_OPER;
            cli_handler(sptr) = CLIENT_HANDLER;
          }
        }
        break;

		/* Invisible al /who */
      case 'i':
        if (what == MODE_ADD)
          SetInvisible(sptr);
        else
          ClearInvisible(sptr);
        break;

		/* No recibe de canales */
      case 'd':
        if (what == MODE_ADD)
          SetDeaf(sptr);
        else
          ClearDeaf(sptr);
        break;

		/* Channel Service */
      case 'k':
        if (what == MODE_ADD)
          SetChannelService(sptr);
        else
          ClearChannelService(sptr);
        break;

		/* Debug mode */
      case 'g':
        if (what == MODE_ADD)
          SetDebug(sptr);
        else
          ClearDebug(sptr);
        break;

		/* Host oculto */
      case 'x':
        if (what == MODE_DEL)
			cli_flags(sptr) &= ~FLAGS_HIDDENHOST;
		else
			cli_flags(sptr) |= FLAGS_HIDDENHOST;
		break;

		/* Operador de ayuda */
	  case 'h':
		  if (what == MODE_ADD)
			  SetHelpOp(sptr);
		  else
			  ClearHelpOp(sptr);
		  break;

		  /* Muestra ips virtuales */
	  case 'X':
		  if (what == MODE_ADD)
			  SetViewip(sptr);
		  else
			  ClearViewip(sptr);
		  break;

		  /* Invisibilidad avanzada */
	  case 'I':
		  if (what == MODE_ADD)
			  SetInvisiblePlus(sptr);
		  else
			  ClearInvisiblePlus(sptr);
		  break;

		  /* Coadmin */
	  case 'c':
		  if (what == MODE_ADD)
			  SetCoadmin(sptr);
		  else
			  ClearCoadmin(sptr);
		  break;

		  /* Admin */
	  case 'a':
		  if (what == MODE_ADD)
			  SetAdmin(sptr);
		  else
			  ClearAdmin(sptr);
		  break;

		  /* Local Admin */
	  case 'A':
		  if (what == MODE_ADD)
			  SetLocAdmin(sptr);
		  else
			  ClearLocAdmin(sptr);
		  break;

		  /* Moderadores */
	  case 'm':
		  if (what == MODE_ADD)
			  SetModera(sptr);
		  else
			  ClearModera(sptr);
		  break;
	  case 'p':
		  if (what == MODE_ADD)
			  SetModera(sptr);
		  else
			  ClearModera(sptr);
		  break;

		  /* Solo recibe privados de usuarios registrados */
	  case 'R':
		  if (what == MODE_ADD)
			  SetOnlyreg(sptr);
		  else
			  ClearOnlyreg(sptr);
		  break;

		  /* Nick registrado o suspendido */
	  case 'S':
		  if (MyUser(sptr))
			  break;
		  if (what == MODE_ADD)
			  SetSuspended(sptr);
		  else
			  ClearSuspended(sptr);
		  break;
	  case 'r':
		  if (MyUser(sptr))
			  break;
		  if (what == MODE_ADD)
			  SetRegnick(sptr);
		  else
			  ClearRegnick(sptr);
		  break;
	  case 'W':
		  if (MyUser(sptr))
			  break;
		  if (what == MODE_ADD)
			  SetWebchatUser(sptr);
		  else
			  ClearWebchatUser(sptr);
		  break;
	  case 'z':
		  if (MyUser(sptr))
			  break;
		  if (what == MODE_ADD)
			  SetSecured(sptr);
		  else
			  ClearSecured(sptr);
		  break;
/*
	  case 'b':
		  if (what == MODE_ADD)
			  SetUserbot(sptr);
		  else
			  ClearUserbot(sptr);
		  break;
	  case 'B':
		  if (what == MODE_ADD)
			  SetBot(sptr);
		  else
			  ClearBot(sptr);
		  break;
*/
      default:
        break;
      }
    }
  }
  /*
   * Evaluate rules for new user mode
   * Stop users making themselves operators too easily:
   */

   if (!IsServer(cptr)) {
    if (!(setflags & FLAGS_OPER) && IsOper(sptr))
      ClearOper(sptr);
    if (!(setflags & FLAGS_LOCOP) && IsLocOp(sptr))
      ClearLocOp(sptr);
    /*
     * new umode; servers can set it, local users cannot;
     * prevents users from /kick'ing or /mode -o'ing
     */
	 /*
     * only send wallops to opers
     */
    if (feature_bool(FEAT_WALLOPS_OPER_ONLY) && !IsAnOper(sptr) &&
	!(setflags & FLAGS_WALLOP))
      ClearWallops(sptr);

    if (feature_bool(FEAT_HIS_SNOTICES_OPER_ONLY) && MyConnect(sptr) && 
	!IsAnOper(sptr) && !es_representante(sptr) && !IsModera(sptr) &&
	!(setflags & FLAGS_SERVNOTICE)) {
      ClearServNotice(sptr);
      set_snomask(sptr, 0, SNO_SET);
    }

    if (feature_bool(FEAT_HIS_DEBUG_OPER_ONLY) && !IsAnOper(sptr) && 
	!(setflags & FLAGS_DEBUG))
      ClearDebug(sptr);
  }

  if (MyConnect(sptr)) {
    if ((setflags & (FLAGS_OPER | FLAGS_LOCOP)) && !IsAnOper(sptr))
      det_confs_butmask(sptr, CONF_CLIENT & ~CONF_OPS);

    if (SendServNotice(sptr)) {
      if (tmpmask != cli_snomask(sptr))
	set_snomask(sptr, tmpmask, SNO_SET);
      if (cli_snomask(sptr) && snomask_given)
	send_reply(sptr, RPL_SNOMASK, cli_snomask(sptr), cli_snomask(sptr));
    } else
      set_snomask(sptr, 0, SNO_SET);
  }
  /*
   * Compare new flags with old flags and send string which
   * will cause servers to update correctly.
   */
  if (!(setflags & FLAGS_OPER) && IsOper(sptr)) { /* user now oper */
    ++UserStats.opers;
    client_set_privs(sptr); /* may set propagate privilege */
  }
  if (HasPriv(sptr, PRIV_PROPAGATE)) /* remember propagate privilege setting */
    prop = 1;
  if ((setflags & FLAGS_OPER) && !IsOper(sptr)) { /* user no longer oper */
    --UserStats.opers;
    client_set_privs(sptr); /* will clear propagate privilege */
  }
  if ((setflags & FLAGS_INVISIBLE) && !IsInvisible(sptr))
    --UserStats.inv_clients;
  if (!(setflags & FLAGS_INVISIBLE) && IsInvisible(sptr))
    ++UserStats.inv_clients;
//  if (!(setflags & FLAGS_HIDDENHOST) && do_host_hiding)
//    hide_hostmask(sptr, FLAGS_HIDDENHOST);


	/* Comprobamos privilegios del usuario */
	if (MyUser(sptr))
		comprueba_privilegios(sptr);

  send_umode_out(cptr, sptr, setflags, rhsetflags, prop);

  return 0;
}

/*
 * Build umode string for BURST command
 * --Run
 */
char *umode_str(struct Client *cptr)
{
  char* m = umodeBuf;                /* Maximum string size: "owidg\0" */
  int   i;
  int   c_flags, c_rhflags;

  c_flags = cli_flags(cptr) & SEND_UMODES; /* cleaning up the original code */
  c_rhflags = cli_rhflags(cptr) & RHFLAGS;
  if (HasPriv(cptr, PRIV_PROPAGATE))
    c_flags |= FLAGS_OPER;
  else
    c_flags &= ~FLAGS_OPER;

  for (i = 0; i < USERMODELIST_SIZE; ++i) {
    if ( (c_flags & userModeList[i].flag))
      *m++ = userModeList[i].c;
  }
  for (i = 0; i < RHUSERMODELIST_SIZE; ++i) {
	  if ( (c_rhflags & RHuserModeList[i].flag))
		  *m++ = RHuserModeList[i].c;
  }

  if (IsAccount(cptr)) {
    char* t = cli_user(cptr)->account;

    *m++ = ' ';
    while ((*m++ = *t++))
      ; /* Empty loop */
  }

  *m = '\0';

  return umodeBuf;                /* Note: static buffer, gets
                                   overwritten by send_umode() */
}

/*
 * Send the MODE string for user (user) to connection cptr
 * -avalon
 */
void send_umode(struct Client *cptr, struct Client *sptr, int old, int oldrh, int sendmask, int rhsendmask)
{
  int i;
  int flag;
  char *m;
  int what = MODE_NULL;

  /*
   * Build a string in umodeBuf to represent the change in the user's
   * mode between the new (sptr->flag) and 'old'.
   */
  m = umodeBuf;
  *m = '\0';
  for (i = 0; i < USERMODELIST_SIZE; ++i) {
    flag = userModeList[i].flag;
    if (MyUser(sptr) && !(flag & sendmask))
      continue;
    if ( (flag & old) && !(cli_flags(sptr) & flag))
    {
      if (what == MODE_DEL)
        *m++ = userModeList[i].c;
      else
      {
        what = MODE_DEL;
        *m++ = '-';
        *m++ = userModeList[i].c;
      }
    }
    else if (!(flag & old) && (cli_flags(sptr) & flag))
    {
      if (what == MODE_ADD)
        *m++ = userModeList[i].c;
      else
      {
        what = MODE_ADD;
        *m++ = '+';
        *m++ = userModeList[i].c;
      }
    }
  }
  for (i = 0; i < RHUSERMODELIST_SIZE; ++i) {
	  flag = RHuserModeList[i].flag;
	  if (MyUser(sptr) && !(flag & rhsendmask))
		  continue;
	  if ( (flag & oldrh) && !(cli_rhflags(sptr) & flag))
	  {
		  if (what == MODE_DEL)
			  *m++ = RHuserModeList[i].c;
		  else {
			  what = MODE_DEL;
			  *m++ = '-';
			  *m++ = RHuserModeList[i].c;
		  }
	  }
	  else if (!(flag & oldrh) && (cli_rhflags(sptr) & flag))
	  {
		  if (what == MODE_ADD)
			  *m++ = RHuserModeList[i].c;
		  else
		  {
			  what = MODE_ADD;
			  *m++ = '+';
			  *m++ = RHuserModeList[i].c;
		  }
	  }
  }
  *m = '\0';
  if (*umodeBuf && cptr)
    sendcmdto_one(sptr, CMD_MODE, cptr, "%s :%s", cli_name(sptr), umodeBuf);
}

/*
 * Check to see if this resembles a sno_mask.  It is if 1) there is
 * at least one digit and 2) The first digit occurs before the first
 * alphabetic character.
 */
int is_snomask(char *word)
{
  if (word)
  {
    for (; *word; word++)
      if (IsDigit(*word))
        return 1;
      else if (IsAlpha(*word))
        return 0;
  }
  return 0;
}

/*
 * If it begins with a +, count this as an additive mask instead of just
 * a replacement.  If what == MODE_DEL, "+" has no special effect.
 */
unsigned int umode_make_snomask(unsigned int oldmask, char *arg, int what)
{
  unsigned int sno_what;
  unsigned int newmask;
  if (*arg == '+')
  {
    arg++;
    if (what == MODE_ADD)
      sno_what = SNO_ADD;
    else
      sno_what = SNO_DEL;
  }
  else if (*arg == '-')
  {
    arg++;
    if (what == MODE_ADD)
      sno_what = SNO_DEL;
    else
      sno_what = SNO_ADD;
  }
  else
    sno_what = (what == MODE_ADD) ? SNO_SET : SNO_DEL;
  /* pity we don't have strtoul everywhere */
  newmask = (unsigned int)atoi(arg);
  if (sno_what == SNO_DEL)
    newmask = oldmask & ~newmask;
  else if (sno_what == SNO_ADD)
    newmask |= oldmask;
  return newmask;
}

static void delfrom_list(struct Client *cptr, struct SLink **list)
{
  struct SLink* tmp;
  struct SLink* prv = NULL;

  for (tmp = *list; tmp; tmp = tmp->next) {
    if (tmp->value.cptr == cptr) {
      if (prv)
        prv->next = tmp->next;
      else
        *list = tmp->next;
      free_link(tmp);
      break;
    }
    prv = tmp;
  }
}

/*
 * This function sets a Client's server notices mask, according to
 * the parameter 'what'.  This could be even faster, but the code
 * gets mighty hard to read :)
 */
void set_snomask(struct Client *cptr, unsigned int newmask, int what)
{
  unsigned int oldmask, diffmask;        /* unsigned please */
  int i;
  struct SLink *tmp;

  oldmask = cli_snomask(cptr);

  if (what == SNO_ADD)
    newmask |= oldmask;
  else if (what == SNO_DEL)
    newmask = oldmask & ~newmask;
  else if (what != SNO_SET)        /* absolute set, no math needed */
    sendto_opmask_butone(0, SNO_OLDSNO, "setsnomask called with %d ?!", what);

  newmask &= (IsAnOper(cptr) ? SNO_ALL : SNO_USER);

  diffmask = oldmask ^ newmask;

  for (i = 0; diffmask >> i; i++) {
    if (((diffmask >> i) & 1))
    {
      if (((newmask >> i) & 1))
      {
        tmp = make_link();
        tmp->next = opsarray[i];
        tmp->value.cptr = cptr;
        opsarray[i] = tmp;
      }
      else
        /* not real portable :( */
        delfrom_list(cptr, &opsarray[i]);
    }
  }
  cli_snomask(cptr) = newmask;
}

/*
 * is_silenced : Does the actual check wether sptr is allowed
 *               to send a message to acptr.
 *               Both must be registered persons.
 * If sptr is silenced by acptr, his message should not be propagated,
 * but more over, if this is detected on a server not local to sptr
 * the SILENCE mask is sent upstream.
 */
int is_silenced(struct Client *sptr, struct Client *acptr)
{
  struct SLink *lp;
  struct User *user;
  static char sender[HOSTLEN + NICKLEN + USERLEN + 5];
  static char senderip[16 + NICKLEN + USERLEN + 5];
  static char senderh[HOSTLEN + ACCOUNTLEN + USERLEN + 6];

  if (!cli_user(acptr) || !(lp = cli_user(acptr)->silence) || !(user = cli_user(sptr)))
    return 0;
  ircd_snprintf(0, sender, sizeof(sender), "%s!%s@%s", cli_name(sptr),
		user->username, get_virtualhost(sptr));
  ircd_snprintf(0, senderip, sizeof(senderip), "%s!%s@%s", cli_name(sptr),
		user->username, ircd_ntoa((const char*) &(cli_ip(sptr))));
  if (HasHiddenHost(sptr))
    ircd_snprintf(0, senderh, sizeof(senderh), "%s!%s@%s", cli_name(sptr),
		  user->username, user->realhost);
  for (; lp; lp = lp->next)
  {
    if ((!(lp->flags & CHFL_SILENCE_IPMASK) && (!match(lp->value.cp, sender) ||
        (HasHiddenHost(sptr) && !match(lp->value.cp, senderh)))) ||
        ((lp->flags & CHFL_SILENCE_IPMASK) && !match(lp->value.cp, senderip)))
    {
      if (!MyConnect(sptr))
      {
        sendcmdto_one(acptr, CMD_SILENCE, cli_from(sptr), "%C %s", sptr,
                      lp->value.cp);
      }
      return 1;
    }
  }
  return 0;
}

/*
 * del_silence
 *
 * Removes all silence masks from the list of sptr that fall within `mask'
 * Returns -1 if none where found, 0 otherwise.
 */
int del_silence(struct Client *sptr, char *mask)
{
  struct SLink **lp;
  struct SLink *tmp;
  int ret = -1;

  for (lp = &(cli_user(sptr))->silence; *lp;) {
    if (!mmatch(mask, (*lp)->value.cp))
    {
      tmp = *lp;
      *lp = tmp->next;
      MyFree(tmp->value.cp);
      free_link(tmp);
      ret = 0;
    }
    else
      lp = &(*lp)->next;
  }
  return ret;
}

int add_silence(struct Client* sptr, const char* mask)
{
  struct SLink *lp, **lpp;
  int cnt = 0, len = strlen(mask);
  char *ip_start;

  for (lpp = &(cli_user(sptr))->silence, lp = *lpp; lp;)
  {
    if (0 == ircd_strcmp(mask, lp->value.cp))
      return -1;
    if (!mmatch(mask, lp->value.cp))
    {
      struct SLink *tmp = lp;
      *lpp = lp = lp->next;
      MyFree(tmp->value.cp);
      free_link(tmp);
      continue;
    }
    if (MyUser(sptr))
    {
      len += strlen(lp->value.cp);
      if ((len > (feature_int(FEAT_AVBANLEN) * feature_int(FEAT_MAXSILES))) ||
	  (++cnt >= feature_int(FEAT_MAXSILES)))
      {
        send_reply(sptr, ERR_SILELISTFULL, mask);
        return -1;
      }
      else if (!mmatch(lp->value.cp, mask))
        return -1;
    }
    lpp = &lp->next;
    lp = *lpp;
  }
  lp = make_link();
  memset(lp, 0, sizeof(struct SLink));
  lp->next = cli_user(sptr)->silence;
  lp->value.cp = (char*) MyMalloc(strlen(mask) + 1);
  assert(0 != lp->value.cp);
  strcpy(lp->value.cp, mask);
  if ((ip_start = strrchr(mask, '@')) && check_if_ipmask(ip_start + 1))
    lp->flags = CHFL_SILENCE_IPMASK;
  cli_user(sptr)->silence = lp;
  return 0;
}

int
send_supported(struct Client *cptr)
{
  char featurebuf[512];

  ircd_snprintf(0, featurebuf, sizeof(featurebuf), FEATURES1, FEATURESVALUES1);
  send_reply(cptr, RPL_ISUPPORT, featurebuf);
  ircd_snprintf(0, featurebuf, sizeof(featurebuf), FEATURES2, FEATURESVALUES2);
  send_reply(cptr, RPL_ISUPPORT, featurebuf);

  return 0; /* convenience return, if it's ever needed */
}

char *get_virtualhost(struct Client *sptr)
{
	if (cli_flags(sptr) & FLAGS_HIDDENHOST) {
		if (cli_user(sptr)->virtualhost[0] == '\0') {
			make_virtualhost(sptr, 0);
		}
		return cli_user(sptr)->virtualhost;
	}
	else {
		return get_realhost(sptr);
	}
}

char *get_realhost(struct Client *sptr)
{
	return cli_user(sptr)->realhost;
}

/*
  make_virtualhost
  Genera la ip virtual de un cliente

  El algoritmo de cifrado de la siguiente función ha sido extraido del ircuH del IRC-Hispano
  http://devel.irc-hispano.org
*/
void make_virtualhost(struct Client *acptr, int mostrar)
{
	char clave[24+1];
	unsigned long v[2], k[4], x[2];
	char c;
	struct db_reg *reg;
	unsigned int ts = 0;
        enum { NO, TABLA_BDD_VHOST, TABLA_BDD_VHOST2 } nueva_ip_personalizada = NO;

	mostrar = mostrar && MyConnect(acptr);

        /* Todo usuario debe de tener el modo +x */
        cli_flags(acptr) |= FLAGS_HIDDENHOST;

	/* Miramos antes de nada el tipo de IP y si debe ser cambiada */
	if ((reg = db_buscar_registro(BDD_VHOSTS, cli_name(acptr))) && (reg->valor))
	{
	  nueva_ip_personalizada = TABLA_BDD_VHOST;
	}
	else if ((reg = db_buscar_registro(BDD_VHOSTS2, cli_name(acptr))) && (reg->valor))
	{
	  nueva_ip_personalizada = TABLA_BDD_VHOST2;
	}

	if ((nueva_ip_personalizada == NO) && (cli_user(acptr)->virtualhost[0] != '\0')
	      && !TieneIpPersonalizada(acptr))
	{
	  return;                     /* No es necesario recalcular la IP virtual */
	}

        /* Cambiamos la IP virtual en funcion del tipo de que sea */
        ClearIpPersonalizada(acptr);
        if (nueva_ip_personalizada == TABLA_BDD_VHOST)
        {
		/* El usuario tiene dirección virtual fija */
                SetIpPersonalizada(acptr);
		strncpy(cli_user(acptr)->virtualhost, reg->valor, HOSTLEN);
	}
        else if (nueva_ip_personalizada == TABLA_BDD_VHOST2)
	{
		/* El usuario tiene dirección virtual semifija */
                SetIpPersonalizada(acptr);
		strncpy(cli_user(acptr)->virtualhost, reg->valor, HOSTLEN);
		strncat(cli_user(acptr)->virtualhost, (utiliza_ipv6(acptr) ? ".vip6" : ".vip"),	HOSTLEN);
	}
	else
	{
		/* En las IPs genericas buscamos la clave de cifrado */
		if (!(reg = db_buscar_registro(BDD_VHOSTS, ".")) || (!reg->valor)) {
			strncpy(cli_user(acptr)->virtualhost, "no.hay.clave.de.cifrado", HOSTLEN);
			return;
		} else {
			strncpy(clave, reg->valor, 24);
			clave[24] = '\0';
		}
		strncat(clave, "AAAAAAAAAAAAAAAAAAAAAAAA", (24-strlen(clave)));
		clave[24] = '\0';

		c = clave[6];
		clave[6] = 0;
		k[0] = base64toint(clave);
		clave[6] = c;

		c = clave[12];
		clave[12] = 0;
		k[1] = base64toint(clave+6);
		clave[12] = c;

		c = clave[18];
		clave[18] = 0;
		k[2] = base64toint(clave+12);
		clave[18] = c;
		k[3] = base64toint(clave+18);

		do {
			x[0] = x[1] = 0;
			v[0] = (k[0] & 0xffff0000) + ts;
			v[1] = ntohl((unsigned long)acptr->cli_ip.s_addr);

			tea(v, k, x);

			memset(cli_user(acptr)->virtualhost, 0, HOSTLEN+1);

			inttobase64(cli_user(acptr)->virtualhost, x[0], 6);
			cli_user(acptr)->virtualhost[6] = '.';
			inttobase64(cli_user(acptr)->virtualhost+7, x[1], 6);
			cli_user(acptr)->virtualhost[13] = '.';
			strcpy(cli_user(acptr)->virtualhost+13,
				(utiliza_ipv6(acptr) ? ".vip6" : ".vip"));

			/* No debería ocurrir nunca... */
			if (++ts == 65535) {
				strcpy(cli_user(acptr)->virtualhost, cli_user(acptr)->realhost);
				break;
			}
		} while (strchr(cli_user(acptr)->virtualhost, ']') || strchr(cli_user(acptr)->virtualhost, '['));
	}
	if (mostrar)
	{
            send_reply(acptr, RPL_HOSTHIDDEN, cli_user(acptr)->virtualhost);
	}

	/* Seteamos el RAW personalizado si procede */
	ClearRawStatus(acptr);
	if ((reg = db_buscar_registro(BDD_RAWSDB, cli_name(acptr))) && (reg->valor))
        {
		SetRawStatus(acptr);
		strncpy(cli_user(acptr)->rawline, reg->valor, RAWLEN);
	}
}
