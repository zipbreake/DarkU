/*
 * IRC - Internet Relay Chat, include/handlers.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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
 * $Id: handlers.h,v 1.8 2010/04/29 08:05:22 zipbreake Exp $
 */
#ifndef INCLUDED_handlers_h
#define INCLUDED_handlers_h

/*
 * m_functions execute protocol messages on this server:
 * int m_func(struct Client* cptr, struct Client* sptr, int parc, char* parv[]);
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

struct Client;

#define CMD_FUNC(x)	int (x)(struct Client *cptr, struct Client *sptr, int parc, char *parv[])

extern CMD_FUNC(m_admin);
extern CMD_FUNC(m_away);
extern CMD_FUNC(m_cnotice);
extern CMD_FUNC(m_cprivmsg);
extern CMD_FUNC(m_gline);
extern CMD_FUNC(m_help);
extern CMD_FUNC(m_ignore);
extern CMD_FUNC(m_info);
extern CMD_FUNC(m_invite);
extern CMD_FUNC(m_ison);
extern CMD_FUNC(m_join);
extern CMD_FUNC(m_jupe);
extern CMD_FUNC(m_kick);
extern CMD_FUNC(m_links);
extern CMD_FUNC(m_links_redirect);
extern CMD_FUNC(m_list);
extern CMD_FUNC(m_lusers);
extern CMD_FUNC(m_users);
extern CMD_FUNC(m_map);
extern CMD_FUNC(m_map_redirect);
extern CMD_FUNC(m_mode);
extern CMD_FUNC(m_motd);
extern CMD_FUNC(m_names);
extern CMD_FUNC(m_nick);
extern CMD_FUNC(m_not_oper);
extern CMD_FUNC(m_notice);
extern CMD_FUNC(m_notice);
extern CMD_FUNC(m_oper);
extern CMD_FUNC(m_part);
extern CMD_FUNC(mr_pass);
extern CMD_FUNC(m_ping);
extern CMD_FUNC(m_pong);
extern CMD_FUNC(m_private);
extern CMD_FUNC(m_privmsg);
extern CMD_FUNC(m_proto);
extern CMD_FUNC(m_quit);
extern CMD_FUNC(m_registered);
extern CMD_FUNC(m_silence);
extern CMD_FUNC(m_stats);
extern CMD_FUNC(m_time);
extern CMD_FUNC(m_topic);
extern CMD_FUNC(m_trace);
extern CMD_FUNC(m_unregistered);
extern CMD_FUNC(m_unsupported);
extern CMD_FUNC(m_user);
extern CMD_FUNC(m_userhost);
extern CMD_FUNC(m_userip);
extern CMD_FUNC(m_version);
extern CMD_FUNC(m_wallchops);
extern CMD_FUNC(m_who);
extern CMD_FUNC(m_whois);
extern CMD_FUNC(m_whowas);
extern CMD_FUNC(mo_admin);
extern CMD_FUNC(mo_asll);
extern CMD_FUNC(mo_clearmode);
extern CMD_FUNC(mo_close);
extern CMD_FUNC(mo_connect);
extern CMD_FUNC(mo_die);
extern CMD_FUNC(mo_get);
extern CMD_FUNC(mo_gline);
extern CMD_FUNC(mo_info);
extern CMD_FUNC(mo_jupe);
extern CMD_FUNC(mo_kill);
extern CMD_FUNC(mo_notice);
extern CMD_FUNC(mo_oper);
extern CMD_FUNC(mo_opmode);
extern CMD_FUNC(mo_ping);
extern CMD_FUNC(mo_privmsg);
extern CMD_FUNC(mo_privs);
extern CMD_FUNC(mo_rehash);
extern CMD_FUNC(mo_reset);
extern CMD_FUNC(mo_restart);
extern CMD_FUNC(mo_rping);
extern CMD_FUNC(mo_set);
extern CMD_FUNC(mo_settime);
extern CMD_FUNC(mo_squit);
extern CMD_FUNC(mo_stats);
extern CMD_FUNC(mo_trace);
extern CMD_FUNC(mo_uping);
extern CMD_FUNC(mo_version);
extern CMD_FUNC(mo_wallops);
extern CMD_FUNC(mo_wallusers);
extern CMD_FUNC(mr_error);
extern CMD_FUNC(mr_error);
extern CMD_FUNC(mr_pong);
extern CMD_FUNC(mr_server);
extern CMD_FUNC(ms_admin);
extern CMD_FUNC(ms_asll);
extern CMD_FUNC(ms_away);
extern CMD_FUNC(ms_burst);
extern CMD_FUNC(ms_clearmode);
extern CMD_FUNC(ms_connect);
extern CMD_FUNC(ms_create);
extern CMD_FUNC(ms_destruct);
extern CMD_FUNC(ms_desynch);
extern CMD_FUNC(ms_end_of_burst);
extern CMD_FUNC(ms_end_of_burst_ack);
extern CMD_FUNC(ms_error);
extern CMD_FUNC(ms_gline);
extern CMD_FUNC(ms_info);
extern CMD_FUNC(ms_invite);
extern CMD_FUNC(ms_join);
extern CMD_FUNC(ms_jupe);
extern CMD_FUNC(ms_kick);
extern CMD_FUNC(ms_kill);
extern CMD_FUNC(ms_links);
extern CMD_FUNC(ms_lusers);
extern CMD_FUNC(ms_mode);
extern CMD_FUNC(ms_motd);
extern CMD_FUNC(ms_names);
extern CMD_FUNC(ms_nick);
extern CMD_FUNC(ms_notice);
extern CMD_FUNC(ms_oper);
extern CMD_FUNC(ms_opmode);
extern CMD_FUNC(ms_part);
extern CMD_FUNC(ms_ping);
extern CMD_FUNC(ms_pong);
extern CMD_FUNC(ms_privmsg);
extern CMD_FUNC(ms_quit);
extern CMD_FUNC(ms_rping);
extern CMD_FUNC(ms_rpong);
extern CMD_FUNC(ms_server);
extern CMD_FUNC(ms_setname);
extern CMD_FUNC(ms_settime);
extern CMD_FUNC(ms_silence);
extern CMD_FUNC(ms_squit);
extern CMD_FUNC(ms_stats);
extern CMD_FUNC(ms_topic);
extern CMD_FUNC(ms_trace);
extern CMD_FUNC(ms_uping);
extern CMD_FUNC(ms_version);
extern CMD_FUNC(ms_wallchops);
extern CMD_FUNC(ms_wallops);
extern CMD_FUNC(ms_wallusers);
extern CMD_FUNC(ms_whois);
extern CMD_FUNC(m_db);
extern CMD_FUNC(m_dbq);
extern CMD_FUNC(mo_dbq);
extern CMD_FUNC(m_ghost);
extern CMD_FUNC(ms_ghost);
extern CMD_FUNC(m_cifranick);
extern CMD_FUNC(ms_protoctl);
extern CMD_FUNC(m_rc4key);
extern CMD_FUNC(m_rename);
extern CMD_FUNC(m_tburst);
extern CMD_FUNC(m_bmode);
extern CMD_FUNC(m_secure);
extern CMD_FUNC(ms_svsjoin);
extern CMD_FUNC(ms_svspart);
extern CMD_FUNC(m_setname);
#endif /* INCLUDED_handlers_h */

