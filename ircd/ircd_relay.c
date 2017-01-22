/*
 * IRC - Internet Relay Chat, ircd/ircd_relay.c
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
 * $Id: ircd_relay.c,v 1.8 2010/06/03 08:21:49 zipbreake Exp $
 */
#include "config.h"

#include "ircd_relay.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* No tocar */
#define ACTION_STR      "ACTION"
#define ACTION_STR_LEN  6

/*
 * This file contains message relaying functions for client and server
 * private messages and notices
 * TODO: This file contains a lot of cut and paste code, and needs
 * to be cleaned up a bit. The idea is to factor out the common checks
 * but not introduce any IsOper/IsUser/MyUser/IsServer etc. stuff.
 */

/*
 * RyDeN
 * Función para quitar los colores de un texto
 */
void correct_colors(char *text)
{
  char *ptr_read, *ptr_write;
  static char forbidden_chars[] = { 2, 15, 22, 31, 0 };
  int parseado;
  ptr_read = ptr_write = text;

  while (*ptr_read)
  {
    do
    {
      parseado = 0;
      /* Colores */
      while (*ptr_read == '\003')
      {
        parseado = !0;
        ptr_read++;
        if (IsDigit(*ptr_read))
        {
          ptr_read++;
          if (IsDigit(*ptr_read))
          {
            ptr_read++;
            if (*ptr_read == ',')
            {
              if (!IsDigit(*(ptr_read + 1)))
              {
                continue;
              }
              else
              {
                ptr_read++;
                if (IsDigit(*++ptr_read))
                {
                  ptr_read++;
                }
              }
            } /* if (*ptr_read == ',') */
          } /* if (IsDigit(*ptr_read)) */
        } /* if (IsDigit(*ptr_read)) */
      }
      /* Otros */
      while ((*ptr_read != '\0') && strchr(forbidden_chars, *ptr_read))
      {
        ptr_read++;
        parseado = !0;
      }
    } while (parseado);

    if (*ptr_read != '\0')
    {
      *ptr_write++ = *ptr_read++;
    }
  }

  *ptr_write = '\0';
}

char *process_badwords(const char *text, int flags);
void relay_channel_message(struct Client* sptr, const char* name, const char* text)
{
  struct Channel* chptr;
  struct Membership *member;
  const char *ch;
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (0 == (chptr = FindChannel(name))) {
    send_reply(sptr, ERR_NOSUCHCHANNEL, name);
    return;
  }
  /*
   * This first: Almost never a server/service
   */
  if (!client_can_send_to_channel(sptr, chptr) && !(cli_flags(sptr) & FLAGS_CHSERV)) {
    send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname, "Moderado");
    return;
  }

  /* Los ctcps empiezan con el ASCII numero 1 */
  if ((strlen(text) > 1) && (chptr->rhmode.mode & RHMODE_NOCTCP) &&
      (text[0] == 1) && (strncasecmp(text+1, ACTION_STR, ACTION_STR_LEN)))
  {
	member = find_member_link(chptr, sptr);
	if (!member || (!es_representante(sptr) && !IsModera(sptr) && !IsVoicedOrOpped(member)))
	{
	   send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname, "No CTCP's");
	   return;
	}
  }

  if ((chptr->mode.mode & MODE_NOPRIVMSGS) &&
      check_target_limit(sptr, chptr, chptr->chname, 0))
    return;

  /* No dejamos enviar al canal colores */
  if ((chptr->rhmode.mode & RHMODE_NOCOLORNOT) && !(cli_flags(sptr) & FLAGS_CHSERV))
    for (ch=text;*ch;ch++)
      if (*ch==3 || *ch==27) {
	send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname, "No Colores");
	return;
  }

  /* Parseo de los colores en el texto a un canal si tiene +c */
  if (MyUser(sptr) && !es_representante(sptr)) {
	  int flags = 0;
	  char *texto_procesado;

	  if (chptr->rhmode.mode & (RHMODE_NOCOLOR | RHMODE_BADWORDS))
		  member = find_member_link(chptr, sptr);

	  if (chptr->rhmode.mode & RHMODE_NOCOLOR) {
		  if (member && !IsVoicedOrOpped(member)) {
			  //int len = strlen(text);
			  correct_colors((char *)text);
			  /*if (len != strlen(text))
			  {
				send_reply(sptr, ERR_NOCOLORSCHAN, chptr->chname);
			  }*/
		  }
	  }

	  if (chptr->rhmode.mode & RHMODE_BADWORDS)
	  {
		  if (member) {
			  if (!(member->status & (CHFL_CHANOP | CHFL_HALFOP)))
				flags = (BADWORDS_CHANNEL | BADWORDS_CHANPRIO);
		  } else
			  flags = (BADWORDS_CHANNEL | BADWORDS_CHANPRIO);
	  }
	  else
		  flags = (BADWORDS_CHANPRIO);

	  if ((texto_procesado = process_badwords(text, flags)) != NULL)
	  {
		sendcmdto_channel_butone(sptr, CMD_PRIVATE, chptr, cli_from(sptr),
		    SKIP_DEAF | SKIP_BURST, "%H :%s", chptr, texto_procesado);
		return;
	  }
  }

  sendcmdto_channel_butone(sptr, CMD_PRIVATE, chptr, cli_from(sptr),
			   SKIP_DEAF | SKIP_BURST, "%H :%s", chptr, text);
}

void relay_channel_notice(struct Client* sptr, const char* name, const char* text)
{
  struct Channel* chptr;
  struct Membership *member;
  const char *ch;
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (0 == (chptr = FindChannel(name)))
    return;
  /*
   * This first: Almost never a server/service
   */
  if (!client_can_send_to_channel(sptr, chptr))
    return;

  if ((chptr->mode.mode & MODE_NOPRIVMSGS) &&
      check_target_limit(sptr, chptr, chptr->chname, 0))
    return;  

  /* No dejamos enviar Notices al canal */
  if ((chptr->rhmode.mode & RHMODE_NONOTICES) && !(cli_flags(sptr) & FLAGS_CHSERV)) {
	send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname, "No Notices");
	return;
  }

  /* No dejamos enviar al canal colores */
  if ((chptr->rhmode.mode & RHMODE_NOCOLORNOT) && !(cli_flags(sptr) & FLAGS_CHSERV))
    for (ch=text;*ch;ch++)
      if (*ch==3 || *ch==27) {
	send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname, "No Colores");
	return;
  }

  /* Parseo de los colores en el texto a un canal si tiene +c */
  if (MyUser(sptr) && !es_representante(sptr)) {
	  int flags = 0;
	  char *texto_procesado;

	  if (chptr->rhmode.mode & (RHMODE_NOCOLOR | RHMODE_BADWORDS))
		  member = find_member_link(chptr, sptr);

	  if (chptr->rhmode.mode & RHMODE_NOCOLOR) {
		  if (member && !IsVoicedOrOpped(member)) {
			  correct_colors((char *)text);
		  }
	  }

	  if (chptr->rhmode.mode & RHMODE_BADWORDS)
	  {
		  if (member) {
			  if (!(member->status & (CHFL_CHANOP | CHFL_HALFOP)))
				flags = (BADWORDS_CHANNEL | BADWORDS_CHANPRIO);
		  } else
			  flags = (BADWORDS_CHANNEL | BADWORDS_CHANPRIO);
	  }
	  else
		  flags = (BADWORDS_CHANPRIO);

	  if ((texto_procesado = process_badwords(text, flags)) != NULL)
	  {
		sendcmdto_channel_butone(sptr, CMD_NOTICE, chptr, cli_from(sptr),
		    SKIP_DEAF | SKIP_BURST, "%H :%s", chptr, texto_procesado);
		return;
	  }
  }

  sendcmdto_channel_butone(sptr, CMD_NOTICE, chptr, cli_from(sptr),
			   SKIP_DEAF | SKIP_BURST, "%H :%s", chptr, text);
}

void server_relay_channel_message(struct Client* sptr, const char* name, const char* text)
{
  struct Channel* chptr;
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (0 == (chptr = FindChannel(name))) {
    /*
     * XXX - do we need to send this back from a remote server?
     */
    send_reply(sptr, ERR_NOSUCHCHANNEL, name);
    return;
  }
  /*
   * This first: Almost never a server/service
   * Servers may have channel services, need to check for it here
   */
  if (client_can_send_to_channel(sptr, chptr) || IsChannelService(sptr)) {
    sendcmdto_channel_butone(sptr, CMD_PRIVATE, chptr, cli_from(sptr),
			     SKIP_DEAF | SKIP_BURST, "%H :%s", chptr, text);
  }
  else
    send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname, "+m");
}

void server_relay_channel_notice(struct Client* sptr, const char* name, const char* text)
{
  struct Channel* chptr;
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (0 == (chptr = FindChannel(name)))
    return;
  /*
   * This first: Almost never a server/service
   * Servers may have channel services, need to check for it here
   */
  if (client_can_send_to_channel(sptr, chptr) || IsChannelService(sptr)) {
    sendcmdto_channel_butone(sptr, CMD_NOTICE, chptr, cli_from(sptr),
			     SKIP_DEAF | SKIP_BURST, "%H :%s", chptr, text);
  }
}


void relay_directed_message(struct Client* sptr, char* name, char* server, const char* text)
{
  struct Client* acptr;
  char*          host;

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);
  assert(0 != server);

  if (0 == (acptr = FindServer(server + 1))) {
    send_reply(sptr, ERR_NOSUCHNICK, name);
    return;
  }
  /*
   * NICK[%host]@server addressed? See if <server> is me first
   */
  if (!IsMe(acptr)) {
    sendcmdto_one(sptr, CMD_PRIVATE, acptr, "%s :%s", name, text);
    return;
  }
  /*
   * Look for an user whose NICK is equal to <name> and then
   * check if it's hostname matches <host> and if it's a local
   * user.
   */
  *server = '\0';
  if ((host = strchr(name, '%')))
    *host++ = '\0';

  /* As reported by Vampire-, it's possible to brute force finding users
   * by sending a message to each server and see which one succeeded.
   * This means we have to remove error reporting.  Sigh.  Better than
   * removing the ability to send directed messages to client servers 
   * Thanks for the suggestion Vampire=.  -- Isomer 2001-08-28
   * Argh, /ping nick@server, disallow messages to non +k clients :/  I hate
   * this. -- Isomer 2001-09-16
   */
  if (!(acptr = FindUser(name)) || !MyUser(acptr) ||
      (!EmptyString(host) && 0 != match(host, cli_user(acptr)->realhost)) ||
      !IsChannelService(acptr)) {
#if 0
    send_reply(sptr, ERR_NOSUCHNICK, name);
#endif
    return;
  }

  *server = '@';
  if (host)
    *--host = '%';

  if (!IsChannelService(sptr) && is_silenced(sptr, acptr)) {
    send_reply(sptr, ERR_SILENCED, cli_name(acptr));
    return;
  }
  
  if (IsOnlyreg(acptr) && !IsRegnick(sptr))
    send_reply(sptr, RPL_MSGONLYREG, cli_name(acptr));
  else
    sendcmdto_one(sptr, CMD_PRIVATE, acptr, "%s :%s", name, text);
}

void relay_directed_notice(struct Client* sptr, char* name, char* server, const char* text)
{
  struct Client* acptr;
  char*          host;

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);
  assert(0 != server);

  if (0 == (acptr = FindServer(server + 1)))
    return;
  /*
   * NICK[%host]@server addressed? See if <server> is me first
   */
  if (!IsMe(acptr)) {
    sendcmdto_one(sptr, CMD_NOTICE, acptr, "%s :%s", name, text);
    return;
  }
  /*
   * Look for an user whose NICK is equal to <name> and then
   * check if it's hostname matches <host> and if it's a local
   * user.
   */
  *server = '\0';
  if ((host = strchr(name, '%')))
    *host++ = '\0';

  if (!(acptr = FindUser(name)) || !MyUser(acptr) ||
      (!EmptyString(host) && 0 != match(host, cli_user(acptr)->realhost)))
    return;

  *server = '@';
  if (host)
    *--host = '%';

  if (!IsChannelService(sptr) && is_silenced(sptr, acptr))
  {
    send_reply(sptr, ERR_SILENCED, cli_name(acptr));
    return;
  }

  if (IsOnlyreg(acptr) && !IsRegnick(sptr))
    send_reply(sptr, RPL_MSGONLYREG, cli_name(acptr));
  else
    sendcmdto_one(sptr, CMD_NOTICE, acptr, "%s :%s", name, text);
}

void relay_private_message(struct Client *cptr, struct Client* sptr, const char* name, const char* text)
{
  struct Client* acptr;
  static char *pmsg = NULL;
  static int last_length = 0;
  int len;

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (0 == (acptr = FindUser(name))) {
    send_reply(sptr, ERR_NOSUCHNICK, name);
    return;
  }
  if (IsOnlyreg(acptr) && !IsRegnick(sptr)) {
	  send_reply(sptr, RPL_MSGONLYREG, cli_name(acptr));
	  return;
  }

  if (!IsChannelService(acptr))
  {
    if (check_target_limit(sptr, acptr, cli_name(acptr), 0))
    {
      return;
    }
    if (is_silenced(sptr, acptr))
    {
      send_reply(sptr, ERR_SILENCED, cli_name(acptr));
      return;
    }
  }

  if (MyUser(cptr) && !es_representante(cptr)) {
	if ((len = strlen(text)+1) > last_length)
	{
		if (pmsg)
			free(pmsg);
		pmsg = (char *)MyMalloc(sizeof(char)*len);
		last_length = len;
	}
	strcpy(pmsg, text);
	correct_colors(pmsg);

    if (process_badwords(pmsg, BADWORDS_QUERY) != NULL)
      return;
  }

  /*
   * send away message if user away
   */
  if (cli_user(acptr) && cli_user(acptr)->away)
    send_reply(sptr, RPL_AWAY, cli_name(acptr), cli_user(acptr)->away);
  /*
   * deliver the message
   */
  if (MyUser(acptr))
    add_target(acptr, sptr);

  sendcmdto_one(sptr, CMD_PRIVATE, acptr, "%C :%s", acptr, text);
}

void relay_private_notice(struct Client *cptr, struct Client* sptr, const char* name, const char* text)
{
  struct Client* acptr;
  static char *pmsg = NULL;
  static int last_length = 0;
  int len;

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (0 == (acptr = FindUser(name)))
    return;
  if (IsOnlyreg(acptr) && !IsRegnick(sptr)) {
	  send_reply(sptr, RPL_MSGONLYREG, cli_name(acptr));
	  return;
  }

  if (!IsChannelService(acptr))
  {
    if (check_target_limit(sptr, acptr, cli_name(acptr), 0))
    {
      return;
    }
    if (is_silenced(sptr, acptr))
    {
      send_reply(sptr, ERR_SILENCED, cli_name(acptr));
      return;
    }
  }

  if (MyUser(cptr) && !es_representante(cptr)) {
	if ((len = strlen(text)+1) > last_length)
	{
		if (pmsg)
			free(pmsg);
		pmsg = (char *)MyMalloc(sizeof(char)*len);
		last_length = len;
	}
	strcpy(pmsg, text);
	correct_colors(pmsg);

    if (process_badwords(pmsg, BADWORDS_QUERY) != NULL)
      return;
  }
    
  /*
   * deliver the message
   */
  if (MyUser(acptr))
    add_target(acptr, sptr);

  sendcmdto_one(sptr, CMD_NOTICE, acptr, "%C :%s", acptr, text);
}

void server_relay_private_message(struct Client* sptr, const char* name, const char* text)
{
  struct Client* acptr;
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);
  /*
   * nickname addressed?
   */
  if (0 == (acptr = findNUser(name)) || !IsUser(acptr)) {
    send_reply(sptr, SND_EXPLICIT | ERR_NOSUCHNICK, "* :Target left %s. "
	       "Failed to deliver: [%.20s]", feature_str(FEAT_NETWORK), text);
    return;
  }

  if (!IsChannelService(sptr) && is_silenced(sptr, acptr))
  {
    send_reply(sptr, ERR_SILENCED, cli_name(acptr));
    return;
  }

  if (IsOnlyreg(acptr) && !IsRegnick(sptr)) {
	  send_reply(sptr, RPL_MSGONLYREG, cli_name(acptr));
	  return;
  }

  if (MyUser(acptr))
    add_target(acptr, sptr);

  sendcmdto_one(sptr, CMD_PRIVATE, acptr, "%C :%s", acptr, text);
}


void server_relay_private_notice(struct Client* sptr, const char* name, const char* text)
{
  struct Client* acptr;
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);
  /*
   * nickname addressed?
   */
  if (0 == (acptr = findNUser(name)) || !IsUser(acptr))
    return;

  if (!IsChannelService(sptr) && is_silenced(sptr, acptr))
  {
    send_reply(sptr, ERR_SILENCED, cli_name(acptr));
    return;
  }

  if (IsOnlyreg(acptr) && !IsRegnick(sptr)) {
	  send_reply(sptr, RPL_MSGONLYREG, cli_name(acptr));
	  return;
  }

  if (MyUser(acptr))
    add_target(acptr, sptr);

  sendcmdto_one(sptr, CMD_NOTICE, acptr, "%C :%s", acptr, text);
}

void relay_masked_message(struct Client* sptr, const char* mask, const char* text)
{
  const char* s;
  int   host_mask = 0;

  assert(0 != sptr);
  assert(0 != mask);
  assert(0 != text);
  /*
   * look for the last '.' in mask and scan forward
   */
  if (0 == (s = strrchr(mask, '.'))) {
    send_reply(sptr, ERR_NOTOPLEVEL, mask);
    return;
  }
  while (*++s) {
    if (*s == '.' || *s == '*' || *s == '?')
       break;
  }
  if (*s == '*' || *s == '?') {
    send_reply(sptr, ERR_WILDTOPLEVEL, mask);
    return;
  }
  s = mask;
  if ('@' == *++s) {
    host_mask = 1;
    ++s;
  }

  sendcmdto_match_butone(sptr, CMD_PRIVATE, s,
			 IsServer(cli_from(sptr)) ? cli_from(sptr) : 0,
			 host_mask ? MATCH_HOST : MATCH_SERVER,
			 "%s :%s", mask, text);
}

void relay_masked_notice(struct Client* sptr, const char* mask, const char* text)
{
  const char* s;
  int   host_mask = 0;

  assert(0 != sptr);
  assert(0 != mask);
  assert(0 != text);
  /*
   * look for the last '.' in mask and scan forward
   */
  if (0 == (s = strrchr(mask, '.'))) {
    send_reply(sptr, ERR_NOTOPLEVEL, mask);
    return;
  }
  while (*++s) {
    if (*s == '.' || *s == '*' || *s == '?')
       break;
  }
  if (*s == '*' || *s == '?') {
    send_reply(sptr, ERR_WILDTOPLEVEL, mask);
    return;
  }
  s = mask;
  if ('@' == *++s) {
    host_mask = 1;
    ++s;
  }

  sendcmdto_match_butone(sptr, CMD_NOTICE, s,
			 IsServer(cli_from(sptr)) ? cli_from(sptr) : 0,
			 host_mask ? MATCH_HOST : MATCH_SERVER,
			 "%s :%s", mask, text);
}

void server_relay_masked_message(struct Client* sptr, const char* mask, const char* text)
{
  const char* s = mask;
  int         host_mask = 0;
  assert(0 != sptr);
  assert(0 != mask);
  assert(0 != text);

  if ('@' == *++s) {
    host_mask = 1;
    ++s;
  }
  sendcmdto_match_butone(sptr, CMD_PRIVATE, s,
			 IsServer(cli_from(sptr)) ? cli_from(sptr) : 0,
			 host_mask ? MATCH_HOST : MATCH_SERVER,
			 "%s :%s", mask, text);
}

void server_relay_masked_notice(struct Client* sptr, const char* mask, const char* text)
{
  const char* s = mask;
  int         host_mask = 0;
  assert(0 != sptr);
  assert(0 != mask);
  assert(0 != text);

  if ('@' == *++s) {
    host_mask = 1;
    ++s;
  }
  sendcmdto_match_butone(sptr, CMD_NOTICE, s,
			 IsServer(cli_from(sptr)) ? cli_from(sptr) : 0,
			 host_mask ? MATCH_HOST : MATCH_SERVER,
			 "%s :%s", mask, text);
}

