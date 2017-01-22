/*
 * IRC - Internet Relay Chat, ircd/s_neg.c
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
 * $Id: s_neg.c,v 1.1.1.1 2006/05/27 13:54:37 zipbreake Exp $
 */
#include "config.h"

#include "IPcheck.h"
#include "channel.h"
#include "client.h"
#include "gline.h"
#include "handlers.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_snprintf.h"
#include "ircd_xopen.h"
#include "jupe.h"
#include "list.h"
#include "match.h"
#include "msg.h"
#include "msgq.h"
#include "numeric.h"
#include "numnicks.h"
#include "parse.h"
#include "querycmds.h"
#include "s_bdd.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_neg.h"
#include "s_serv.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"
#include "sys.h"
#include "userload.h"
#include "zlib.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>


/* Estructura de las negociaciones */
struct Configs configs[] = {
//	{ "ZLIB", NEGOCIACION_ZLIB_IN, NEGOCIACION_ZLIB_OUT, NEGOCIACION_ZLIB_SPEC, inicia_zlib },
//	{ "RC4",  NEGOCIACION_RC4_WAITING, NEGOCIACION_RC4_OUT, NEGOCIACION_RC4_SPEC, inicia_rc4 },
	{ "TOKEN", 0, NEGOCIACION_TOKEN_OUT, NEGOCIACION_TOKEN_SPEC, NULL },
	NULL
};


void envia_negociaciones(struct Client *cptr)
{
	struct Configs *conf;
	char conf_str[1024];

	for (*conf_str = '\0', conf = configs; conf && conf->name; conf++) {
		strcat(conf_str, conf->name);
		strcat(conf_str, " ");
	}

	if (*conf_str) {
		*(conf_str + strlen(conf_str) - 1) = '\0';
		sendcmdto_one(&me, CMD_PROTOCTL, cptr, NEG_REQ " :%s", conf_str);
	}
}

void acepta_negociaciones(struct Client *cptr, unsigned int old)
{
	struct Configs *conf;
	char ack_str[1024];
	unsigned int negociaciones = cli_negociacion(cptr);

	*ack_str = '\0';

	for (conf = configs; conf && (conf->name); conf++) {
		if ((negociaciones & conf->flag_spec) && !(old & conf->flag_spec)) {
			strcat(ack_str, conf->name);
			strcat(ack_str, " ");
			negociaciones &= ~(conf->flag_spec);
			negociaciones |= conf->flag_out;
			if (conf->funcion_procesado != NULL)
				conf->funcion_procesado(cptr, 1);
		}
	}

	if (*ack_str && MyConnect(cptr)) {
		*(ack_str + strlen(ack_str) - 1) = '\0';
		sendcmdto_one(&me, CMD_PROTOCTL, cptr, NEG_ACK " :%s", ack_str);
		cli_negociacion(cptr) = negociaciones;
	}
}


/* Negociaciones */

/***********************************************************************/
/*                                 ZLIB                                */
/***********************************************************************/
/* Compresión server <=> server
   Extraído del ircu del IRC-Hispano http://www.irc-hispano.org
   */
voidpf z_alloc(voidpf opaque, uInt items, uInt size)
{
  return MyCalloc(items, size);
}

void z_free(voidpf opaque, voidpf address)
{
  MyFree(address);
}

P_NEG(inicia_zlib)
{
	int estado;

	if (!tipo_negociacion) {
		cptr->comp_in = MyMalloc(sizeof(z_stream));
		cptr->comp_in->next_in = Z_NULL;
		cptr->comp_in->avail_in = 0;
		cptr->comp_in->zalloc = z_alloc;
		cptr->comp_in->zfree = z_free;
		cptr->comp_in->opaque = 0;
		estado = inflateInit(cptr->comp_in);
		assert(estado == Z_OK);
		cptr->comp_in_total_in = 0;
		cptr->comp_in_total_out = 0;
	} else {
		cptr->comp_out = MyMalloc(sizeof(z_stream));
		cptr->comp_out->zalloc = z_alloc;
		cptr->comp_out->zfree = z_free;
		cptr->comp_out->opaque = 0;
		estado = deflateInit(cptr->comp_out, 9);
		assert(estado == Z_OK);
		cptr->comp_out_total_in = 0;
		cptr->comp_out_total_out = 0;
	}
}


/***********************************************************************/
/*                                 RC4                                 */
/***********************************************************************/

char *crea_clave_rc4(struct Client *cptr)
{
	unsigned int v[2], x[2], k[4];
	int n = 32;
	static char clave[12 + 1];
	struct rc4_state *estado_rc4;
	unsigned int w = 0;

	memset(clave, 0, sizeof(clave));

	x[0] = x[1] = time(NULL)^0xffff^(unsigned int)&cptr;

	v[0] = base64toint(cli_name(cptr));
	v[1] = base64toint(cli_name(&me));

	w = v[0] ^ v[1];

	k[0] = w ^ 0x1234;
	k[1] = w ^ 0xffff;
	k[2] = w ^ 0xf0f0;
	k[3] = w ^ 0x0f0f;

	while (n--)
		tea(v, k, x);
	
	inttobase64(clave, x[0], 6);
	inttobase64(clave+6, x[1], 6);

	return clave;
}

P_NEG(inicia_rc4)
{
	char *clave;
	struct rc4_state *estado_rc4;

	if (!tipo_negociacion) {
		if (cptr->estado_rc4_in != NULL) {
			cli_negociacion(cptr) |= NEGOCIACION_RC4_IN;
			cli_negociacion(cptr) &= ~NEGOCIACION_RC4_WAITING;
			return;
		}
	} else {

	clave = crea_clave_rc4(cptr);
	estado_rc4 = (struct rc4_state *)rc4_initstate(clave, 12);
	assert(0 != estado_rc4);
	cptr->estado_rc4_out = estado_rc4;
	sendcmdto_one(&me, CMD_RC4KEY, cptr, clave);

	}
}

