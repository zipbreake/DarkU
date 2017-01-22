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
 * $Id: s_bdd.c,v 1.14 2010/04/29 12:22:23 zipbreake Exp $
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
#include "handlers.h"
#include "hash.h"
#include "ircd.h"
#include "channel.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "jupe.h"
#include "list.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "querycmds.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_serv.h"
#include "send.h"
#include "userload.h"
#include "s_bdd.h"
#include "s_debug.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Tablas activas */
static int tabla_activa_access(char *clave, char *valor);
static int tabla_activa_config(char *clave, char *valor);
static int tabla_activa_joins(char *clave, char *valor);
static int tabla_activa_vhosts(char*,char*);
static int tabla_activa_canales(char*,char*,char*);
static int tabla_activa_flags(char*,char*);
static int tabla_activa_users(char*,char*);
static int tabla_activa_rawsdb(char*,char*);
typedef int (*tablas_activas_t)(char*,char*);
typedef int (*tablas_activas2_t)(char*,char*,char*);
tablas_activas_t tablas_activas[BDD_TOTAL];
tablas_activas2_t tablas_activas2[BDD_TOTAL];

/* Vectores */
unsigned long tabla_registros[BDD_TOTAL][2];
unsigned long tabla_residente[BDD_TOTAL];
unsigned long tabla_hash[BDD_TOTAL][2];
struct db_reg **primer_db[BDD_TOTAL];
struct db2_reg **primer_db2[BDD_TOTAL];
short tabla_corrupta[BDD_TOTAL];
time_t tabla_modificado[BDD_TOTAL];

/* Funciones externas */
int tabla_es_residente(char db);
unsigned int db_hash_registro(char *clave, int len);

/* Uso interno */
static inline void inicia_actividad(void);
static inline void abrir_db(db_file *fichero, char db, unsigned long registro);
static inline int leer_db(db_file *fichero, char *buf, size_t max_length);
static inline void seek_db(db_file *fichero, unsigned long registro);
static inline void cerrar_db(db_file *fichero);
static inline void inicia_db(char db, int tabla_version);
static inline void db_actualiza_hash(char *registro, char db);
void db_die(char *formatmsg, ...);
static inline void db_empty_table(char tabla, unsigned int tipo_tabla);

/* Búsqueda */
struct db_reg *db_buscar_registro(char db, char *clave);
struct db2_reg *db2_buscar_registro(char db, char *clave);
struct _db2_valores_ *db2_buscar_subclave(char db, char *clave, char *subclave);
struct _db2_valores_ *db2_buscar_en_registro(struct db2_reg *reg, char *clave);

/* Hash/corrupción */
inline int tabla_es_corrupta(char db);
static inline void db_tabla_comprueba_corrupcion(char db, int tabla_version);
static inline void db_almacena_hash(char db);
static inline void db_get_hash_str(char db, char *dest1, char *dest2);
static inline void db_get_hash(char db, unsigned long *dest1, unsigned long *dest2, int tabla_version);

/* Segmentado de líneas de registro */
static inline void db_segmenta_registro(char *registro, char **serie, char **destino, char **clave,
    char **clave_fin, char **valor, char **valor_fin);
static inline void db_segmenta_registro2(char *registro, char **serie, char **destino, char **clave,
    char **clave_fin, char **valor_clave, char **valor_clave_fin,
    char **valor, char **valor_fin);

/* Insertado de registros */
static inline void db_inserta_registro(struct Client *cptr, char db, char *registro, char *serie,
    char *destino, char *clave,
    char *clave_fin, char *valor, char *valor_fin, int addr);
static inline void db_inserta_registro2(struct Client *cptr, 
    char db, char *registro, char *serie, char *destino, char *clave,
    char *clave_fin, char *valor_clave, char *valor_clave_fin,
    char *valor, char *valor_fin, int addr);

/* Funciones de protocolo */
static inline void db_tabla_join(struct Client* cptr, struct Client* sptr, int parc, char* parv[]);
static inline void db_tabla_join_activos(struct Client *cptr, struct Client* sptr, int parc, char* parv[]);
static inline void db_tabla_delete(struct Client* cptr, struct Client* sptr, int parc, char* parv[]);
static inline void db_pack(char db, char *registro);
static inline void db_max_pack(char db, char *registro);
static inline void db_tabla_checkhash(struct Client* cptr, struct Client* sptr, int parc, char *parv[]);

/* Iterador */
struct db_reg *db_iterador_init(char tabla);
struct db2_reg *db2_iterador_init(char tabla);
struct db_reg *db_iterador_next(void);
struct db2_reg *db2_iterador_next(void);
static struct db_reg *db_iterador_first(void);
static struct db2_reg *db2_iterador_first(void);
static char db_iterador_tabla;
static struct db_reg *db_iterador_registro;
static struct db2_reg *db2_iterador_registro;
static unsigned long db_iterador_hash;
static unsigned long db_iterador_hash_len;

/* Temporalmente lo ponemos en mayusculas */
char *DB_DIR = "database";

char *cifranick(char *nickname, char *password)
{
  /*
    RyDeN --
    Algoritmo de encriptación extraído del ircuH (http://devel.irc-hispano.org)
    y modificado para adaptarlo al ircuRH
  */
  unsigned int v[2], w[2], k[4];
  int cont = (NICKLEN + 8)/8;
  char tmpnick[8 * ((NICKLEN + 8)/8) + 1];
  char tmppass[24 + 1];
  unsigned int *p = (unsigned int *)tmpnick;
  static char temp[13];

  memset(tmppass, 0, sizeof(tmppass));
  strncpy(tmppass, password, sizeof(tmppass)-1);
  strncat(tmppass, "AAAAAAAAAAAAAAAAAAAAAAAA", sizeof(tmppass)-strlen(tmppass)-1);

  memset(tmpnick, 0, sizeof(tmpnick));
  strncpy(tmpnick, nickname, sizeof(tmpnick)-1);

  k[3] = base64toint(tmppass + 18);

  tmppass[18] = '\0';
  k[2] = base64toint(tmppass + 12);

  tmppass[12] = '\0';
  k[1] = base64toint(tmppass + 6);

  tmppass[6] = '\0';
  k[0] = base64toint(tmppass);

  w[0] = w[1] = 0;
  
  while (cont--)
  {
    v[0] = ntohl(*p++);
    v[1] = ntohl(*p++);
    tea(v, k, w);
  }
  inttobase64(temp, w[0], 6);
  inttobase64(temp+6, w[1], 6);
  return temp;
}

CMD_FUNC(m_cifranick)
{
  char *ptr = parv[1];

  if (IsServer(cptr))
  {
    return 0;
  }

  if (parc < 3)
  {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Uso: CIFRANICK <nick> <password>", sptr);
    return need_more_params(sptr, "CIFRANICK");
  }

  while (*ptr)
  {
    *ptr = ToLower(*ptr);
    ptr++;
  }

  sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :CIFRANICK OK %s %s", sptr, parv[1],
      cifranick(parv[1], parv[2]));

  return 0;
}

/*
 * m_db - Bases de Datos
 *
 * En caso de nuevo registro:
 *    parv[0] = sender prefix
 *    parv[1] = Servidor destino
 *    parv[2] = Numero de serie
 *    parv[3] = tabla
 *    parv[4] = clave del registro
 *   Si parc es mayor que 5:
 *    parv[parc-1] = valor
 *
 *
 * En caso de JOIN:
 *    parv[0] = sender prefix
 *    parv[1] = Servidor destino
 *    parv[2] = sin uso
 *    parv[3] = comando (J)
 *    parv[4] = serie de DB local remota
 *    parv[5] = tabla
 */
CMD_FUNC(m_db)
{
  unsigned short es_hub = 0;
  char tabla;
  assert(IsServer(cptr));

  if (!feature_bool(FEAT_BDD_SUPPORT))
  {
    return 0;
  }

  if (parc < 5)
  {
    return 0;
  }

  if (*(parv[3] + 1) != '\0')
  {
    return 0;
  }
  
  if ((find_conf_byname(cli_confs(cptr), cli_name(cptr), CONF_HUB)) != NULL)
  {
    es_hub = !0;
  }
  /* Nos curamos en salud */
  if ((parc == 6) && (*parv[5] == '\0'))
  {
    --parc;
  }
  if ((parc == 7) && (*parv[6] == '\0'))
  {
    --parc;
  }

  if (cli_serv(cptr)->bdd_version == 2)
  {
    switch (*parv[2])
    {
      case 'J':
        db_tabla_join(cptr, sptr, parc, parv);
        return 0;
      case 'A':
        db_tabla_join_activos(cptr, sptr, parc, parv);
        return 0;
      case 'R':
        return 0;
      case 'D':
        if (es_hub)
        {
          db_tabla_delete(cptr, sptr, parc, parv);
        }
        return 0;
      case 'H':
        if (es_hub)
        {
          db_tabla_checkhash(cptr, sptr, parc, parv);
        }
        return 0;
      default:
        /* Nuevo registro */
        if (!es_hub)
        {
          return 0;
        }

        if (parc < 5)
        {
          return 0;
        }


        tabla = *parv[3];

        if ((tabla < BDD2_START || tabla > BDD2_END) && (tabla < BDD_START || tabla > BDD_END))
        {
          return 0;
        }

        do
        {
          char buffer[4096];
          char *serie, *destino, *clave, *clave_fin;
          char *valor_clave, *valor_clave_fin, *valor, *valor_fin;
          struct DLink *lp;
          unsigned int grifo = 1;
          int tipo_tabla;

          if (tabla >= BDD2_START && tabla <= BDD2_END)
          {
            tipo_tabla = 2;
          }
          else if (tabla >= BDD_START && tabla <= BDD_END)
          {
            tipo_tabla = 1;
          }

          if (tipo_tabla == 2)
          {
            if (parc == 5)
            {
              /* No hay valor ni subclave, es un borrado */
              sprintf(buffer, "%09lu %s %s\n", atol(parv[2]), parv[1], parv[4]);
            }
            else if (parc == 6)
            {
              /* Hay subclave */
              sprintf(buffer, "%09lu %s %s %s\n", atol(parv[2]), parv[1], parv[4], parv[5]);
            }
            else if (parc > 6)
            {
              /* Hay subclave y valor */
              sprintf(buffer, "%09lu %s %s %s %s\n", atol(parv[2]), parv[1], parv[4], parv[5], parv[parc-1]);
            }
            else
            {
              /* No debería ocurrir nunca */
              protocol_violation(sptr, "Numero de parametros en comando DB incorrecto");
              return 0;
            }

            grifo <<= (tabla-BDD2_START);

            for (lp = cli_serv(&me)->down; lp; lp = lp->next)
            {
              if ((lp->value.cptr != cptr) &&
                     (cli_serv(lp->value.cptr)->rhdbs2_abiertas & grifo) &&
                     (cli_serv(lp->value.cptr)->bdd_version == 2))
              {
                if (parc == 5)
                {
                  sendcmdto_one(&me, CMD_DB, lp->value.cptr, "%s %09lu %c %s",
                      parv[1], atol(parv[2]), tabla, parv[4]);
                }
                else if (parc == 6)
                {
                  sendcmdto_one(&me, CMD_DB, lp->value.cptr, "%s %09lu %c %s %s",
                      parv[1], atol(parv[2]), tabla, parv[4], parv[5]);
                }
                else
                {
                  sendcmdto_one(&me, CMD_DB, lp->value.cptr, "%s %09lu %c %s %s :%s",
                      parv[1], atol(parv[2]), tabla, parv[4], parv[5], parv[parc-1]);
                }
              }  
            }

            db_segmenta_registro2(
                buffer, &serie, &destino, &clave, &clave_fin, &valor_clave, &valor_clave_fin, &valor, &valor_fin
		);
            db_inserta_registro2(
                cptr, tabla, buffer, serie, destino, clave, clave_fin, valor_clave, valor_clave_fin, valor, valor_fin, 1
		);
          }

          else if (tipo_tabla == 1)
          {
            if (parc == 5)
            {
              /* No hay valor, es un borrado */
              sprintf(buffer, "%09lu %s %s\n", atol(parv[2]), parv[1], parv[4]);
            }
            else if (parc > 5)
            {
              /* Hay valor */
              sprintf(buffer, "%09lu %s %s %s\n", atol(parv[2]), parv[1], parv[4], parv[parc-1]);
            }
            else
            {
              /* No debería ocurrir nunca */
              protocol_violation(sptr, "Numero de parametros en comando DB incorrecto");
              return 0;
            }

            grifo <<= (tabla-BDD_START);

            for (lp = cli_serv(&me)->down; lp; lp = lp->next)
            {
              if ((lp->value.cptr != cptr) &&
                            (cli_serv(lp->value.cptr)->rhdbs_abiertas & grifo))
              {
                if (parc > 5)
                {
                  sendcmdto_one(&me, CMD_DB, lp->value.cptr, "%s %09lu %c %s :%s",
                                    parv[1], atol(parv[2]), tabla, parv[4], parv[parc-1]
                                    );
                }
                else
                {
                  sendcmdto_one(&me, CMD_DB, lp->value.cptr, "%s %09lu %c %s",
                                    parv[1], atol(parv[2]), tabla, parv[4]
                                    );
                }
              }  
            }

            db_segmenta_registro(buffer, &serie, &destino, &clave, &clave_fin, &valor, &valor_fin);
            db_inserta_registro(cptr, tabla, buffer, serie, destino, clave, clave_fin, valor, valor_fin, 1);
          }
        } while (0);
        return 0;
    }

  }
  else
  {

    if ((cli_serv(cptr)->bdd_version == 0) && *parv[3] != 'J')
    {
      return 0;  /* Nos curamos en salud */
    }

    switch (*parv[3])
    {
      case 'J':
        db_tabla_join(cptr, sptr, parc, parv);
        return 0;
      case 'A':
        db_tabla_join_activos(cptr, sptr, parc, parv);
        return 0;
      case 'R':
        return 0;
      case 'D':
        if (es_hub)
        {
          db_tabla_delete(cptr, sptr, parc, parv);
        }
        return 0;
      case 'H':
        if (es_hub)
        {
          db_tabla_checkhash(cptr, sptr, parc, parv);
        }
        return 0;
      default:
        /* Nuevo registro */
        if (!es_hub)
        {
          return 0;
        }
        tabla = *parv[3];
        if (tabla < BDD_START || tabla > BDD_END)
        {
          return 0;
        }

        do
        {
          char buffer[4096];
          char *serie, *destino, *clave, *clave_fin, *valor, *valor_fin;

          if (parc == 5)
          {
            /* No hay valor, es un borrado */
            sprintf(buffer, "%09lu %s %s\n", atol(parv[2]), parv[1], parv[4]);
          }
          else if (parc > 5)
          {
            /* Hay valor */
            sprintf(buffer, "%09lu %s %s %s\n", atol(parv[2]), parv[1], parv[4], parv[parc-1]);
          }
          else
          {
            /* No debería ocurrir nunca */
            protocol_violation(sptr, "Numero de parametros en comando DB incorrecto");
            return 0;
          }

          if (!strcmp(parv[4], "*"))
          {
            db_pack(tabla, buffer);
          }
          else if (!strcmp(parv[4], "**"))
          {
            db_max_pack(tabla, buffer);
          }
          else
          {
          struct DLink *lp;
          unsigned int grifo = 1;

          grifo <<= (tabla-BDD_START);

          for (lp = cli_serv(&me)->down; lp; lp = lp->next)
          {
            if ((lp->value.cptr != cptr) &&
                (cli_serv(lp->value.cptr)->rhdbs_abiertas & grifo))
            {
              if (parc > 5)
              {
                sendcmdto_one(&me, CMD_DB, lp->value.cptr, "%s %09lu %c %s :%s",
                    parv[1], atol(parv[2]), tabla, parv[4], parv[parc-1]
                    );
              }
              else
              {
                sendcmdto_one(&me, CMD_DB, lp->value.cptr, "%s %09lu %c %s",
                    parv[1], atol(parv[2]), tabla, parv[4]
                    );
              }
            }  
          }

          db_segmenta_registro(buffer, &serie, &destino, &clave, &clave_fin, &valor, &valor_fin);
          db_inserta_registro(cptr, tabla, buffer, serie, destino, clave, clave_fin, valor, valor_fin, 1);
          }
        } while (0);
        return 0;
    }
  }
}


/* Desconecta todos los hubs menos 'one' */
static inline void desconecta_hubs_butone(struct Client *one, char *exitmsg)
{
  struct DLink *lp, *lp2;
  struct Client *acptr;

  for (lp = cli_serv(&me)->down; lp; lp = lp2)
  {
    lp2 = lp->next;

    acptr = lp->value.cptr;
    if ((acptr != one) &&
        find_conf_byname(cli_confs(acptr), cli_name(acptr), CONF_HUB))
    {
      exit_client(acptr, acptr, &me, exitmsg);
    }
  }
}

static inline void db_tabla_join_activos(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char tabla = *parv[parc-1];
  int tabla_version;

  /* Tabla no residente */
  if (!tabla_es_residente(tabla) || !(cli_serv(sptr)->bdd_version))
  {
    return;
  }

  if (tabla >= BDD_START && tabla <= BDD_END)
  {
    tabla_version = 1;
  }
  else if (tabla >= BDD2_START && tabla <= BDD_END)
  {
    tabla_version = 2;
  }
  else
  {
    return;
  }

  if (cli_serv(sptr)->bdd_version == 1)
  {
    struct db_reg *reg;
    
    for (reg = db_iterador_init(tabla); reg != NULL; reg = db_iterador_next())
    {
      sendcmdto_one(&me, CMD_DB, cptr, "* 0 R %c %s :%s", tabla, reg->clave, reg->valor);
    }
  }

  else if (cli_serv(sptr)->bdd_version == 2)
  {
    if (tabla_version == 1)
    {
      struct db_reg *reg;
      for (reg = db_iterador_init(tabla); reg != NULL; reg = db_iterador_next())
      {
        sendcmdto_one(&me, CMD_DB, cptr, "* R 0 %c %s :%s", tabla, reg->clave, reg->valor);
      }
    }
    else if (tabla_version == 2)
    {
      struct db2_reg *reg;
      struct _db2_valores_ *v;
      for (reg = db2_iterador_init(tabla); reg != NULL; reg = db2_iterador_next())
      {
        for (v = reg->valor; v; v = v->next)
        {
          sendcmdto_one(&me, CMD_DB, cptr, "* R 0 %c %s :+%s %s",
              tabla, reg->clave, v->clave, v->valor
              );
        }
      }
    }
  } /* else if (cli_serv(sptr)->bdd_version == 2) */
}
static inline void db_tabla_join(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char tabla = *parv[parc-1];
  db_file fichero;
  char buf[1025];
  char hashtabla[13];
  int len;
  unsigned long grifo = 1;
  unsigned int bdd_version = cli_serv(cptr)->bdd_version;
  int tipo_tabla;
  char *serie, *destino, *clave, *clave_fin, *valor, *valor_fin, *valor_clave, *valor_clave_fin;

  if (parc != 6)
  {
    return;
  }

  if ((bdd_version == 0) && (tabla >= '1' && tabla <= '9'))
  {
    unsigned int tablav = atoi(parv[parc-1]);

    /* Nos mandan su versión de la BDD */
    cli_serv(cptr)->bdd_version = tablav;
    if (find_conf_byname(cli_confs(cptr), cli_name(cptr), CONF_HUB) != NULL)
    {
      if (tablav == 1)
      {
        char c;
        for (c = BDD_START; c <= BDD_END; c++)
        {
          sendcmdto_one(&me, CMD_DB, cptr, "* 0 J %09lu %c", tabla_registros[(int)c][0], c);
        }
      }

      else if (tablav == 2)
      {
        char c;

        for (c = BDD_START; c <= BDD_END; c++)
        {
          sendcmdto_one(&me, CMD_DB, cptr, "* J 0 %09lu %c", tabla_registros[(int)c][0], c);
        }

        for (c = BDD2_START; c <= BDD2_END; c++)
        {
          sendcmdto_one(&me, CMD_DB, cptr, "* J 0 %09lu %c", tabla_registros[(int)c][0], c);
        }
      }
    }
    return;
  }

  /* Solo puede hacer join a tablas si nos ha especificado su versión */
  if (bdd_version == 0)
  {
    return;
  }

  if (bdd_version == 1)
  {
    if (tabla < BDD_START || tabla > BDD_END)
    {
      return;
    }
  }
  else if (bdd_version == 2)
  {
    if ((tabla < BDD2_START || tabla > BDD2_END) && (tabla < BDD_START || tabla > BDD_END))
    {
      return;
    }
  }
  else
  {
    return;
  }

  /* Comprobamos qué tipo de tabla están solicitando */
  if (tabla > BDD_START && tabla < BDD_END)
    tipo_tabla = 1;
  else if (tabla > BDD2_START && tabla < BDD2_END)
    tipo_tabla = 2;

  if (tipo_tabla == 1)
  {
    grifo <<= (tabla-BDD_START);
    cli_serv(cptr)->rhdbs_abiertas |= grifo;
  }
  else if (tipo_tabla == 2)
  {
    grifo <<= (tabla-BDD2_START);
    cli_serv(cptr)->rhdbs2_abiertas |= grifo;
  }

  abrir_db(&fichero, tabla, atol(parv[4])+1);
  while ((len = leer_db(&fichero, buf, sizeof(buf)-1)) != -1)
  {
    if (tipo_tabla == 1)
    {
      db_segmenta_registro(buf, &serie, &destino, &clave, &clave_fin, &valor, &valor_fin);
      if (!clave)
      {
        continue;
      }
      *clave_fin = '\0';
      *(clave - 1) = '\0';
      *(destino - 1) = '\0';

      if (valor)
      {
        *valor_fin = '\0';
        sendcmdto_one(&me, CMD_DB, cptr, "%s %09lu %c %s :%s", destino, atol(serie), tabla, clave, valor);
      }
      else
      {
        sendcmdto_one(&me, CMD_DB, cptr, "%s %09lu %c %s", destino, atol(serie), tabla, clave);
      }
    }

    else if (tipo_tabla == 2)
    {
      db_segmenta_registro2(buf, &serie, &destino, &clave, &clave_fin, &valor_clave, &valor_clave_fin, &valor, &valor_fin);
      if (!clave)
      {
        continue;
      }

      *clave_fin = '\0';
      *(clave - 1) = '\0';
      *(destino - 1) = '\0';

      if (!valor_clave)
      {
        sendcmdto_one(&me, CMD_DB, cptr, "%s %09lu %c %s", destino, atol(serie), tabla, clave);
      }
      else if (!valor)
      {
        *valor_clave_fin = '\0';
        sendcmdto_one(&me, CMD_DB, cptr, "%s %09lu %c %s %s", destino, atol(serie), tabla, clave, valor_clave);
      }
      else
      {
        *valor_clave_fin = '\0';
        *valor_fin = '\0';
        sendcmdto_one(&me, CMD_DB, cptr, "%s %09lu %c %s %s :%s", destino, atol(serie), tabla, clave, valor_clave, valor);
      }
    }
  }
  cerrar_db(&fichero);

  /*
   * RyDeN - 16 Mayo 2004
   *
   * Una vez finalizada la sincronización, enviamos la comprobación de hash de la tabla.
   * Importante: Esta comprobación NUNCA DEBE ENVIARSE A UN HUB, ya que si falla la DB de
   * un hub, se borran las DBs de toda la red
   */
  if ((find_conf_byname(cli_confs(cptr), cli_name(cptr), CONF_HUB)) != NULL)
  {
    return;
  }

  inttobase64(hashtabla, tabla_hash[tabla][0], 6);
  inttobase64(hashtabla+6, tabla_hash[tabla][1], 6);
  if (bdd_version == 1)
  {
    sendcmdto_one(&me, CMD_DB, cptr, "* 0 H %s %c", hashtabla, tabla);
  }
  else if (bdd_version == 2)
  {
    sendcmdto_one(&me, CMD_DB, cptr, "* H 0 %s %c", hashtabla, tabla);
  }
}


/* Borrado de una tabla */
static inline void db_empty_table(char tabla, unsigned int tipo_tabla)
{
  char path[1024];
  int handle;

  /* Borramos todas las estructuras de esta tabla */
  if (tipo_tabla == 1)
  {
    struct db_reg *reg, *reg2;

    for (reg = db_iterador_init(tabla); reg != NULL; reg = reg2)
    {
      reg2 = db_iterador_next();

      /* Es necesario que al borrar una tabla se realice la actividad de los borrados */
      if (tablas_activas[tabla])
      {
        tablas_activas[tabla](reg->clave, NULL);
      }
      MyFree(reg->clave);
      MyFree(reg->valor);
      MyFree(reg);
    }

    /* Inicializamos los buckets de la tabla */
    memset(primer_db[tabla], 0, sizeof(struct db_reg *)*tabla_residente[tabla]);
  }

  else if (tipo_tabla == 2)
  {
    struct db2_reg *reg, *reg2;
    struct _db2_valores_ *v, *v2;

    for (reg = db2_iterador_init(tabla); reg != NULL; reg = reg2)
    {
      reg2 = db2_iterador_next();

      for (v = reg->valor; v; v = v2)
      {
        v2 = v->next;
        if (tablas_activas2[tabla])
        {
          tablas_activas2[tabla](reg->clave, v->clave, NULL);
        }
        MyFree(v->clave);
        MyFree(v->valor);
        MyFree(v);
      }
      MyFree(reg->clave);
      MyFree(reg);
    }

    /* Inicializamos los buckets de la tabla */
    memset(primer_db2[tabla], 0, sizeof(struct db2_reg *)*tabla_residente[tabla]);
  }

  /* Se procede al borrado del fichero */
  sprintf(path, "%s/tabla.%c", DB_DIR, tabla);
  handle = open(path, O_TRUNC, S_IREAD | S_IWRITE);
  if (handle == -1)
  {
    db_die("Error al borrar db %c (open)", tabla);
  }
  close(handle);

  /* Inicializamos el hash */
  tabla_hash[tabla][0] = tabla_hash[tabla][1] = 0;
  db_almacena_hash(tabla);

  /* Inicializamos los datos de la tabla */
  tabla_corrupta[tabla] = 0;
  tabla_registros[tabla][0] = tabla_registros[tabla][1] = 0;
  tabla_modificado[tabla] = time(NULL);
}

static inline void db_tabla_delete(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  int tipo_tabla;
  char tabla = *parv[5];
  char path[1024];
  char *destino = parv[1];
  struct DLink *lp;

  collapse(destino);

  /* Enviamos el mensaje al resto de servidores */
  for (lp = cli_serv(&me)->down; lp; lp = lp->next)
  {
    if ((lp->value.cptr != cptr) && cli_serv(lp->value.cptr)->bdd_version)
    {
      if (cli_serv(lp->value.cptr)->bdd_version == 1)
      {
        sendcmdto_one(&me, CMD_DB, lp->value.cptr, "%s 0 D 0 %c",
            destino, tabla
            );
      }
      else if (cli_serv(lp->value.cptr)->bdd_version == 2)
      {
        sendcmdto_one(&me, CMD_DB, lp->value.cptr, "%s D 0 0 %c",
            destino, tabla
            );
      }
    }  
  }


  /* No nos concierne a nosotros dicho borrado */
  if (match(destino, cli_name(&me)))
  {
    return;
  }

  /* Buscamos el tipo de tabla del que se trata */
  if (cli_serv(cptr)->bdd_version == 1)
  {
    if ((tabla >= BDD_START) && (tabla <= BDD_END))
    {
      tipo_tabla = 1;
    }
    else
    {
      return;
    }
  }
  else
  {
    if ((tabla >= BDD_START) && (tabla <= BDD_END))
    {
      tipo_tabla = 1;
    }
    else if ((tabla >= BDD2_START) && (tabla <= BDD2_END))
    {
      tipo_tabla = 2;
    }
    else
    {
      return;
    }
  }

  /* Vaciamos la tabla */
  db_empty_table(tabla, tipo_tabla);

  /* Cortamos la conexion con los hubs menos con el que nos envia
     la peticion de borrado para resincronizarlos
  */
  sprintf(path, "Resincronizando Base de Datos tras borrado de tabla '%c'", tabla);
  desconecta_hubs_butone(cptr, path);

  /* Tras un borrado de una tabla el grifo se corta */
  if (tipo_tabla == 1)
  {
    cli_serv(cptr)->rhdbs_abiertas &= ~(1 << (tabla - BDD_START));
  }
  else if (tipo_tabla == 2)
  {
    cli_serv(cptr)->rhdbs_abiertas &= ~(1 << (tabla - BDD2_START));
  }

  /* Solicitamos de nuevo la tabla */
  if (cli_serv(cptr)->bdd_version == 1)
  {
    sendcmdto_one(&me, CMD_DB, cptr, "* 0 J 0 %c", tabla);
  }
  else if (cli_serv(cptr)->bdd_version == 2)
  {
    sendcmdto_one(&me, CMD_DB, cptr, "* J 0 0 %c", tabla);
  }
}

/*
 * RyDeN - 16 Mayo 2004
 *
 * Comprobación de hash de una tabla para leafs
 *
 */
static inline void db_tabla_checkhash(struct Client* cptr, struct Client* sptr, int parc, char *parv[])
{
  unsigned int hash_hi, hash_lo;
  char c;
  char tabla;
  char *hash;
  unsigned int tipo_tabla;

  if (parc < 6)
  {
    return;
  }

  tabla = *parv[5];

  /* Un HUB de la red nunca debería recibir comprobaciones de HASH, salvo que un nodo malicioso la envíe,
     pudiendo ocasionar un borrado de la tabla especificada */

  if (feature_bool(FEAT_HUB))
  {
    protocol_violation(sptr,
        "Intento de envío de comprobación de HASH de la tabla '%c' siendo yo un HUB", tabla
        );
    return;
  }

  /* Seteamos los hashes */
  hash = parv[4];
  if (strlen(hash) != 12)
  {
    /* El hash siempre debe tener un ancho de 12 caracteres */
    protocol_violation(sptr, "Comprobacion de HASH con numero de hash de ancho incorrecto");
    return;
  }
  c = hash[6];
  hash[6] = '\0';
  hash_lo = base64toint(hash);
  hash[6] = c;
  hash_hi = base64toint(hash+6);

  if ((hash_lo == tabla_hash[tabla][0]) || (hash_hi == tabla_hash[tabla][1]))
  {
    return;
  }
  
  sendto_opmask_butone(NULL, SNO_OLDSNO,
      "Comprobación de HASH fallida, el HASH de la tabla '%c' no coincide con el de %C. Resincronizando tabla...",
      tabla, sptr
      );

  /* Para resincronizar la tabla, primero hay que borrarla */
  if (tabla >= BDD2_START && tabla <= BDD2_END)
  {
    tipo_tabla = 2;
  }
  else if (tabla >= BDD_START && tabla <= BDD_END)
  {
    tipo_tabla = 1;
  }
  db_empty_table(tabla, tipo_tabla);

  /* Solicitamos de nuevo la tabla */
  if (cli_serv(cptr)->bdd_version == 1)
  {
    sendcmdto_one(&me, CMD_DB, cptr, "* 0 J 000000000 %c", tabla);
  }
  else if (cli_serv(cptr)->bdd_version == 2)
  {
    sendcmdto_one(&me, CMD_DB, cptr, "* J 0 000000000 %c", tabla);
  }
}

static inline void db_pack(char db, char *registro)
{
  /* Listo para implementar */
}

static inline void db_max_pack(char db, char *registro)
{
  /* Para hacer, será una mejora del anterior que consuma más CPU y memoria
  pero que compacte al máximo la base de datos */
}

/*
 *
 * db_die
 *
 */

void db_die(char *formatmsg, ...)
{
  struct Client *acptr;
  int i;

  char diemsg[1024];
  char diemsg2[1024];
  va_list vl;

  va_start(vl, formatmsg);
  vsprintf(diemsg2, formatmsg, vl);
  va_end(vl);

  sprintf(diemsg, "Database error: %s", diemsg2);

  for (i = 0; i <= HighestFd; i++)
  {
    if (!(acptr = LocalClientArray[i]))
    {
      continue;
    }
    if (IsUser(acptr))
    {
      sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :%s", acptr, diemsg);
    }
    else if (IsServer(acptr))
    {
      sendcmdto_one(&me, CMD_ERROR, acptr, ":%s", diemsg);
    }
  }
  server_die(diemsg);
}


/*
 *
 * abrir_db
 *
 */
static inline void abrir_db(db_file *fichero, char db, unsigned long registro)
{
  char db_path[100];
  int handle;

  sprintf(db_path, "%s/tabla.%c", DB_DIR, db);

  handle = open(db_path, O_RDONLY | O_CREAT, S_IREAD|S_IWRITE);
  fstat(handle, &(fichero->estado));
  fichero->map_p = mmap(NULL, fichero->estado.st_size, PROT_READ, MAP_SHARED | MAP_NORESERVE, handle, 0);

  if (handle == -1)
  {
    db_die("Error al abrir db %c (open)", db);
  }
  if ((fichero->estado.st_size > 0) && (fichero->map_p == MAP_FAILED))
  {
    db_die("Error al abrir db %c (mmap)", db);
  }
  close(handle);

  fichero->read_p = fichero->map_p;
  if (registro > 1)
  {
    seek_db(fichero, registro);
  }
}


/*
 *
 * cerrar_db
 *
 */
static inline void cerrar_db(db_file *fichero)
{
  munmap(fichero->map_p, fichero->estado.st_size);
}


/*
 *
 * seek_db
 *
 */
static inline void seek_db(db_file *fichero, unsigned long registro)
{
  char *ptrhi, *ptrlo, *p1, *p2;
  unsigned long serie;

  /* Seek por bidivisión, extraído del ircuH, escrito por jcea (http://www.argo.es/~jcea/)
  http://devel.irc-hispano.org
  */
    ptrlo = fichero->map_p;
    ptrhi = ptrlo + fichero->estado.st_size;

  while (ptrlo != ptrhi)
  {
    p1 = p2 = ptrlo + ((ptrhi - ptrlo) / 2);

    while ((p1 >= ptrlo) && (*p1 != '\n'))
    {
      --p1;
    }
    if (p1 < ptrlo)
    {
      p1 = ptrlo;
    }
    while ((p2 <= ptrhi) && (*p2++ != '\n'));

    serie = atol(p1);
    if (serie < registro)
    {
      ptrlo = p2;
    }
    else if (serie > registro)
    {
      ptrhi = p1;
    }
    else
    {
      ptrhi = ptrlo = p1;
      break;
    }
  }

  fichero->read_p = ptrlo;
}


/*
 *
 * borrar_db
 *
 */
static inline void borrar_db(char db, int tabla_version)
{
  int i;

  if (!tabla_es_residente(db))
  {
    return;
  }

  if (tabla_version == 1)
  {
    struct db_reg *reg, *reg2;
    
    if (primer_db[db])
    {
      for (reg = db_iterador_init(db); reg != NULL; reg = reg2)
      {
        reg2 = db_iterador_next();

        assert(reg->clave);
        MyFree(reg->clave);

        assert(reg->valor);
        MyFree(reg->valor);

        MyFree(reg);
      }
    }
    else
    {
      primer_db[db] = (struct db_reg **)MyMalloc(sizeof(struct db_reg *)*tabla_residente[db]);
    }
    memset(primer_db[db], 0, sizeof(struct db_reg *)*tabla_residente[db]);
    tabla_registros[db][0] = tabla_registros[db][1] = 0;
    tabla_hash[db][0] = tabla_hash[db][1] = 0;
  }
  
  else if (tabla_version == 2)
  {
    struct db2_reg *reg, *reg2;
    
    if (primer_db2[db])
    {
      struct _db2_valores_ *v, *v2;
        
      for (reg = db2_iterador_init(db); reg != NULL; reg = reg2)
      {
        reg2 = db2_iterador_next();
          
        assert(reg->clave);
        MyFree(reg->clave);
              
        assert(reg->valor);
        for (v = reg->valor; v != NULL; v = v2)
        {
          v2 = v->next;
                
          assert(v->clave);
          MyFree(v->clave);
                
          assert(v->valor);
          MyFree(v->valor);
                
          MyFree(v);
        }
              
        MyFree(reg);
      }
    }
    else
    {
      primer_db2[db] = (struct db2_reg **)MyMalloc(sizeof(struct db2_reg *)*tabla_residente[db]);
    }
    memset(primer_db2[db], 0, sizeof(struct db2_reg *)*tabla_residente[db]);
    tabla_registros[db][0] = tabla_registros[db][1] = 0;
    tabla_hash[db][0] = tabla_hash[db][1] = 0;
  }
}
 
/*
 *
 * db_segmenta_registro
 *
 */

static inline void db_segmenta_registro(char *registro, char **serie, char **destino, char **clave,
             char **clave_fin, char **valor, char **valor_fin)
{
  char *ptr;
  *serie = NULL;
  *destino = NULL;
  *clave = NULL;
  *clave_fin = NULL;
  *valor = NULL;
  *valor_fin = NULL;

  *serie = ptr = registro;
  ptr = strchr(ptr, 32);
  if (!ptr)
  {
    return;
  }
  *destino = ++ptr;
  ptr = strchr(ptr, 32);
  if (!ptr)
  {
    return;
  }
  *clave = ++ptr;
  while (*ptr != '\0' && *ptr != '\n' && *ptr != 32)
  {
    ptr++;
  }
  *clave_fin = ptr;
  if (*ptr != 32)
  {
    return;
  }
  *valor = ++ptr;
  while (*ptr != '\0' && *ptr != '\n')
  {
    ptr++;
  }
  *valor_fin = ptr;
  if (*valor == *valor_fin)
  {
    *valor = *valor_fin = NULL;
  }
}


/*
 *
 * db_segmenta_registro2
 * Variación de db_segmenta_registro() para la DB2
 *
 */

static inline void db_segmenta_registro2(char *registro, char **serie, char **destino, char **clave,
             char **clave_fin, char **valor_clave, char **valor_clave_fin,
             char **valor, char **valor_fin)
{
  char *ptr;
  *serie = NULL;
  *destino = NULL;
  *clave = NULL;
  *clave_fin = NULL;
  *valor_clave = NULL;
  *valor_clave_fin = NULL;
  *valor = NULL;
  *valor_fin = NULL;

  *serie = ptr = registro;
  ptr = strchr(ptr, 32);
  if (!ptr)
  {
    return;
  }
  *destino = ++ptr;
  ptr = strchr(ptr, 32);
  if (!ptr)
  {
    return;
  }
  *clave = ++ptr;
  while (*ptr != '\0' && *ptr != '\n' && *ptr != 32)
  {
    ptr++;
  }
  *clave_fin = ptr;
  if (*ptr != 32)
  {
    return;
  }
  *valor_clave = ++ptr;
  while (*ptr != '\0' && *ptr != '\n' && *ptr != 32)
  {
    ptr++;
  }
  *valor_clave_fin = ptr;
  if (*ptr != 32)
  {
    return;
  }
  *valor = ++ptr;
  while (*ptr != '\0' && *ptr != '\n')
  {
    ptr++;
  }
  *valor_fin = ptr;
  if (*valor == *valor_fin)
  {
    *valor = *valor_fin = NULL;
  }
}
/*
 *
 * leer_db
 *
 */
static inline int leer_db(db_file *fichero, char *buf, size_t max_length)
{
  int len = 0;
  int handle;
  char *ptr = fichero->read_p;
  char *fin = fichero->map_p + fichero->estado.st_size;

  while (ptr < fin)
  {
    if (*ptr == '\n')
    {
      fichero->read_p = ++ptr;
      *buf = '\0';
      return len;
    }
    else if (*ptr == '\r')
    {
      continue;
    }
    else if (++len >= max_length)
    {
      break;
    }
    else
    {
      *buf++ = *ptr;
    }
    ++ptr;
  }
  *buf = '\0';
  fichero->read_p = ptr;
  return -1;
}

/*
 *
 * db_buscar_registro
 *
 * No usamos el db_iterador para obtener un mayor rendimiento ya que esta
 * función se utiliza mucho a lo largo del ircd. Lo mismo ocurre con el
 * db2_buscar_registro.
 */
struct db_reg *db_buscar_registro(char db, char *clave)
{
  struct db_reg *find;
  
  if (!tabla_es_residente(db))
  {
    return (struct db_reg *)NULL;
  }

  for (find = primer_db[db][db_hash_registro(clave, tabla_residente[db])];
      find != NULL;
      find = find->next)
  {
    if (!ircd_strcmp(clave, find->clave))
    {
      return find;
    }
  }
  
  return (struct db_reg *)NULL;
}

/*
 *
 * db2_buscar_registro
 *
 */
struct db2_reg *db2_buscar_registro(char db, char *clave)
{
  struct db2_reg *find;
  
  if (!tabla_es_residente(db))
  {
    return (struct db2_reg *)NULL;
  }

  for (find = primer_db2[db][db_hash_registro(clave, tabla_residente[db])];find;find=find->next)
  {
    if (!ircd_strcmp(clave, find->clave))
    {
      return find;
    }
  }
  return (struct db2_reg *)NULL;
}

struct _db2_valores_ *db2_buscar_subclave(char db, char *clave, char *subclave)
{
  struct db2_reg *reg;
  struct _db2_valores_ *v;

  if ((reg = db2_buscar_registro(db, clave)) == NULL)
  {
    return NULL;
  }
  if ((v = db2_buscar_en_registro(reg, subclave)))
  {
    return v;
  }
  return NULL;
}

struct _db2_valores_ *db2_buscar_en_registro(struct db2_reg *reg, char *clave)
{
  struct _db2_valores_ *find;

  assert(reg);

  for (find = reg->valor; find; find = find->next)
  {
    if (!ircd_strcmp(clave, find->clave))
    {
      return find;
    }
  }
  return (struct _db2_valores_ *)NULL;
}


/*
 *
 * borra_registro
 *
 */
static inline void borra_registro(char db, char *clave)
{
  struct db_reg *del, *prev;
  unsigned int rhash;

  rhash = db_hash_registro(clave, tabla_residente[db]);

    /* Hago una búsqueda sin utilizar db_buscar_registro() para así
     conseguir la estructura anterior a la que vamos a borrar */
  prev = NULL;
  for (del = primer_db[db][rhash];del;del=del->next)
  {
    if (!ircd_strcmp(clave, del->clave))
    {
      break;
    }
    prev = del;
  }

  /* No existe el registro, paramos */
  if (!del)
  {
    return;
  }

  if (!prev)
  {
    /* El registro es el primero en la lista */
    primer_db[db][rhash] = del->next;
  }
  else
  {
    prev->next = del->next;
  }

  if (del->valor)
  {
    MyFree(del->valor);
  }
  MyFree(del);

  tabla_registros[db][1]--;
}

/*
 *
 * borra_registro2
 *
 */
static inline void borra_registro2(char db, char *clave)
{
  struct db2_reg *del, *prev;
  unsigned int rhash;

  rhash = db_hash_registro(clave, tabla_residente[db]);

    /* Hago una búsqueda sin utilizar db_buscar_registro() para así
     conseguir la estructura anterior a la que vamos a borrar */
  prev = NULL;
  for (del = primer_db2[db][rhash];del;del=del->next)
  {
    if (!ircd_strcmp(clave, del->clave))
    {
      break;
    }
    prev = del;
  }

  /* No existe el registro, paramos */
  if (!del)
  {
    return;
  }

  if (!prev)
  {
    /* El registro es el primero en la lista */
    primer_db2[db][rhash] = del->next;
  }
  else
  {
    prev->next = del->next;
  }

  if (del->clave)
  {
    MyFree(del->clave);
  }
  if (del->valor)
  {
    struct _db2_valores_ *v, *v2;
    for (v = del->valor; v; v = v2)
    {
      v2 = v->next;
      if (v->clave)
      {
        MyFree(v->clave);
      }
      if (v->valor)
      {
        MyFree(v->valor);
      }
      MyFree(v);
    }
  }
  MyFree(del);

  tabla_registros[db][1]--;
}

/*
 *
 * db_inserta_registro
 *
 */
static inline void db_inserta_registro(struct Client *cptr, char db, char *registro, char *serie,
    char *destino, char *clave, char *clave_fin,
    char *valor, char *valor_fin, int addr)
{
  struct db_reg *add;
  unsigned long seriel;
  char c;
  int i;

  /* No se puede insertar nunca un registro sin clave */
  assert(0 != clave);
  
  if (!tabla_es_residente(db))
  {
    return;
  }

  c = *(destino - 1);
  *(destino - 1) = '\0';
  collapse(destino);
  seriel = atol(serie);
  /* ¿? nos envian una serie menor que la que tenemos de esa db ¿? */
  if (tabla_registros[db][0] >= seriel)
  {
    return;
  }
  tabla_registros[db][0] = seriel;

  *(destino - 1) = c;

  if (addr)
  {
    int handle;
    char db_path[1024];
    struct stat estado;

    assert(registro && *registro);
    sprintf(db_path, "%s/tabla.%c", DB_DIR, db);

    handle = open(db_path, O_CREAT|O_APPEND|O_WRONLY, S_IREAD|S_IWRITE);
    if (handle == -1)
    {
      db_die("Error al escribir fichero de db %c (open)", db);
    }
    if (write(handle, registro, strlen(registro)) == -1)
    {
      db_die("Error al escribir fichero de db %c (write)", db);
    }

    close(handle);
    stat(db_path, &estado);
    tabla_modificado[db] = estado.st_mtime;

    db_actualiza_hash(registro, db);
    db_almacena_hash(db);
  }

  /* Es para mi */
  do
  {
    *(clave - 1) = '\0';
    if (!match(destino, cli_name(&me)))
    {
      *clave_fin = '\0';

      if (!valor || !*valor)
      {
        borra_registro(db, clave);
        break;
      }
  
      if (valor_fin)
      {
        *valor_fin = '\0';
      }

      if (!(add = db_buscar_registro(db, clave)))
      {
        unsigned int rhash = db_hash_registro(clave, tabla_residente[db]);
        char *ptr;

        /* El registro no existe, asi que lo creamos y añadimos */
        add = (struct db_reg *)MyMalloc(sizeof(struct db_reg));
        memset(add, 0, sizeof(struct db_reg));
        add->next = primer_db[db][rhash];

        add->clave = strdup(clave);
      
        primer_db[db][rhash] = add;
        tabla_registros[db][1]++;
      }

      if (add->valor)
      {
        MyFree(add->valor);
      }
      add->valor = strdup(valor);
    }
  } while (0);

  if ((cptr != NULL) && tablas_activas[db] != NULL)
  {
    tablas_activas[db](clave, valor);
  }
}

/*
 *
 * db_inserta_registro2
 * Modificación de inserta_registro() para la DB2
 *
 */
static inline void db_inserta_registro2(struct Client *cptr, char db, char *registro, char *serie,
    char *destino, char *clave, char *clave_fin,
    char *valor_clave, char *valor_clave_fin,
    char *valor, char *valor_fin, int addr)
{
  struct db2_reg *add;
  unsigned long seriel;
  char c;
  int i, direction;

  if (!tabla_es_residente(db))
  {
    return;
  }

  c = *(destino - 1);
  *(destino - 1) = '\0';
  seriel = atol(serie);
  /* ¿? nos envian una serie menor que la que tenemos de esa db ¿? */
  if (tabla_registros[db][0] >= seriel)
  {
    return;
  }
  tabla_registros[db][0] = seriel;

  *(destino - 1) = c;

  if (addr)
  {
    int handle;
    char db_path[1024];
    struct stat estado;

    assert(registro && *registro);
    sprintf(db_path, "%s/tabla.%c", DB_DIR, db);

    handle = open(db_path, O_CREAT|O_APPEND|O_WRONLY, S_IREAD|S_IWRITE);
    if (handle == -1)
    {
      db_die("Error al escribir fichero de db %c (open)", db);
    }
    if (write(handle, registro, strlen(registro)) == -1)
    {
      db_die("Error al escribir fichero de db %c (write)", db);
    }

    close(handle);
    stat(db_path, &estado);
    tabla_modificado[db] = estado.st_mtime;

    db_actualiza_hash(registro, db);
    db_almacena_hash(db);
  }

  *(clave - 1) = '\0';
  if (match(destino, cli_name(&me)))
  {
    return;      /* No es para mi */
  }

  *clave_fin = '\0';
  if (valor_clave == NULL)
  {
    /* Es un borrado */
    borra_registro2(db, clave);
    goto actividad;
    /* Comprobar tablas activas, al final de la función */
  }

  if (*valor_clave != '+' && *valor_clave != '-')
  {
    /* Protocolo erróneo */
    return;
  }

  direction = (*valor_clave == '+') ? !0 : 0;

  valor_clave++;

  if (valor == NULL && direction == 1)
  {
    /* Agregando un registro sin clave */
    return;
  }

  if ((add = db2_buscar_registro(db, clave)) == NULL)
  {
    unsigned int rhash;
    /* Nuevo registro */
    if (direction == 0)
    {
      /* No pueden enviarnos un borrado de una clave del registro si no existía */
      return;
    }

    add = (struct db2_reg *)MyMalloc(sizeof(struct db2_reg));
    memset(add, 0, sizeof(struct db2_reg));

    add->clave = strdup(clave);

    add->valor = (struct _db2_valores_ *)MyMalloc(sizeof(struct _db2_valores_));
    memset(add->valor, 0, sizeof(struct _db2_valores_));

    *valor_clave_fin = '\0';
    *valor_fin = '\0';
    add->valor->clave = strdup(valor_clave);
    add->valor->valor = strdup(valor);

    rhash = db_hash_registro(add->clave, tabla_residente[db]);

    add->next = primer_db2[db][rhash];
    primer_db2[db][rhash] = add;

    tabla_registros[db][1]++;

    goto actividad; /* Al final de la funcion */
  }

  if (direction == 1)
  {
    /* Agregamos datos a una clave */
    struct _db2_valores_ *v, *v2;

    *valor_clave_fin = '\0';
    *valor_fin = '\0';

    if (add->valor == NULL)
    {
      /* No debería ocurrir nunca, pero por si acaso, nos curamos en salud */
      add->valor = (struct _db2_valores_ *)MyMalloc(sizeof(struct _db2_valores_));
      v = add->valor;
      memset(v, 0, sizeof(struct _db2_valores_));
      v->clave = (char *)MyMalloc(sizeof(char)*(strlen(valor_clave)+1));
      strcpy(v->clave, valor_clave);
      v->valor = (char *)MyMalloc(sizeof(char)*(strlen(valor)+1));
      strcpy(v->valor, valor);
      goto actividad; /* Al final de la funcion */
    }

    for (v = add->valor; v != NULL; v = v->next)
    {
      v2 = v;
      if (strcasecmp(v->clave, valor_clave) == 0)
      {
        break;
      }
    }

    if (v == NULL && v2)
    {
      v2->next = (struct _db2_valores_ *)MyMalloc(sizeof(struct _db2_valores_));
      memset(v2->next, 0, sizeof(struct _db2_valores_));
      v = v2->next;
      v->clave = (char *)MyMalloc(sizeof(char)*(strlen(valor_clave)+1));
      strcpy(v->clave, valor_clave);
      v->valor = (char *)MyMalloc(sizeof(char)*(strlen(valor)+1));
      strcpy(v->valor, valor);
    }
    else
    {
      if (v->valor)
      {
        MyFree(v->valor);
      }
      v->valor = (char *)MyMalloc(sizeof(char)*(strlen(valor)+1));
      strcpy(v->valor, valor);
    }
  }
  else
  {
    struct _db2_valores_ *v, *v2 = NULL;

    *valor_clave_fin = '\0';
    for (v = add->valor; v; v = v->next)
    {
      if (!strcmp(v->clave, valor_clave))
      {
        break;
      }
      v2 = v;
    }

    if (v == NULL)
    {
      /* Nos piden un borrado en un registro que no existe */
      return;
    }

    if (v2 == NULL)
    {
      /* El valor a borrar es el primero de la lista */
      add->valor = v->next;
    }
    else
    {
      v2->next = v->next;
    }

    if (v->clave)
    {
      MyFree(v->clave);
    }
    if (v->valor)
    {
      MyFree(v->valor);
    }

    if (add->valor == NULL)
    {
      /* El registro ha sido borrado entero */
      borra_registro2(db, clave);
    }
  }

actividad:
  if (valor_clave)
  {
    --valor_clave;
  }

  if ((cptr != NULL) && tablas_activas2[db] != NULL)
  {
    tablas_activas2[db](clave, valor_clave, valor);
  }
}


/*
 *
 * tabla_es_residente
 *
 */
int tabla_es_residente(char db)
{
  return ((tabla_residente[db] > 0) ? 1 : 0);
}

/*
 *
 * inicia_actividad
 *
 */
static inline void inicia_actividad(void)
{
  tablas_activas['l'] = tabla_activa_access;
  tablas_activas['c'] = tabla_activa_config;
  tablas_activas['f'] = tabla_activa_flags;
  tablas_activas['j'] = tabla_activa_joins;
  tablas_activas['n'] = tabla_activa_users;
  tablas_activas['r'] = tabla_activa_rawsdb;
  tablas_activas['v'] = tabla_activa_vhosts;
  tablas_activas['w'] = tabla_activa_vhosts;
  tablas_activas2['C'] = tabla_activa_canales;  /* DB2 */
}

/*
 *
 * inicia_dbs
 *
 */
void inicia_dbs(void)
{
  char actdb;
  static int actividad_iniciada = 0;

  if (!feature_bool(FEAT_BDD_SUPPORT))
  {
    return;
  }

  if (!actividad_iniciada)
  {
    inicia_actividad();
    actividad_iniciada = 1;
  }

  sendto_opmask_butone(0, SNO_OLDSNO, "Leyendo Bases de Datos...");

  /* Establecemos las tablas residentes y sus longitudes */
  memset(&tabla_residente, 0, BDD_TOTAL);
  tabla_residente[BDD_NICKS] = 16384; /* Por el momento, va de sobra para GenteChat */
  tabla_residente[BDD_ACCESS] = 128;
  tabla_residente[BDD_CONFIG] = 128;
  tabla_residente[BDD_FLAGS] = 256;
  tabla_residente[BDD_RAWSDB] = 512;
  tabla_residente[BDD_VHOSTS] = 512;
  tabla_residente[BDD_VHOSTS2] = 512;
  tabla_residente[BDD_BOTS] = 64;
  tabla_residente[BDD_ILINES] = 128;
  tabla_residente[BDD_CHANNELS] = 512;
  tabla_residente[BDD_BADWORDS] = 1;
  tabla_residente[BDD_JOINS] = 256;

  /* Iniciamos todas las dbs */
  for (actdb = BDD_START; actdb<= BDD_END; actdb++)
  {
    inicia_db(actdb, 1);
  }

  for (actdb = BDD2_START; actdb <= BDD2_END; actdb++)
  {
    inicia_db(actdb, 2);
  }

}

/*
 *
 * inicia_db
 *
 */
static inline void inicia_db(char db, int tabla_version)
{
  db_file fichero;
  char buf[1025], buf2[2048];
  int len;
  char *serie, *destino, *clave, *clave_fin, *valor, *valor_fin, *valor_clave, *valor_clave_fin;
  struct stat estado;
  char db_path[1024];
  int tabla_valida = (db >= BDD_START && db <= BDD_END) || (db >= BDD2_START && db <= BDD2_END);
  int stat_ok;

  assert(db);
  assert(tabla_valida);

  sprintf(db_path, "%s/tabla.%c", DB_DIR, db);
  stat_ok = stat(db_path, &estado);

  if (!tabla_es_corrupta(db) && (stat_ok != -1) && estado.st_mtime == tabla_modificado[db])
  {
    /* No hay cambios, no es necesario releer la tabla */
    return;
  }

  borrar_db(db, tabla_version);
  abrir_db(&fichero, db, 0);

  while ((len = leer_db(&fichero, buf, sizeof(buf)-1)) != -1)
  {
    db_actualiza_hash(buf, db);
    if (tabla_version == 1)
    {
      db_segmenta_registro(buf, &serie, &destino, &clave, &clave_fin, &valor, &valor_fin);
    }
    else if (tabla_version == 2)
    {
      db_segmenta_registro2(buf, &serie, &destino, &clave, &clave_fin, &valor_clave,
          &valor_clave_fin, &valor, &valor_fin);
    }
    if (!clave)
    {
      continue;
    }
    if (tabla_version == 1)
    {
      db_inserta_registro(NULL, db, NULL, serie, destino, clave, clave_fin, valor,
          valor_fin, 0);
    }
    else if (tabla_version == 2)
    {
      db_inserta_registro2(NULL, db, NULL, serie, destino, clave, clave_fin, valor_clave,
          valor_clave_fin, valor, valor_fin, 0);
    }
  }

  cerrar_db(&fichero);

  stat(db_path, &estado);
  tabla_modificado[db] = estado.st_mtime;

  db_tabla_comprueba_corrupcion(db, tabla_version);
  if (!tabla_es_corrupta(db))
  {
    if (tabla_es_residente(db))
    {
      sendto_opmask_butone(0, SNO_OLDSNO, "Tabla '%c' S=%09lu",
          db, tabla_registros[db][0]);
    }
    else if (tabla_registros[db][0])
    {
      sendto_opmask_butone(0, SNO_OLDSNO, "Tabla '%c' S=%09lu NO_RESIDENTE",
          db, tabla_registros[db][0]);
    }
  }
  else
  {
    sendto_opmask_butone(0, SNO_OLDSNO, "Tabla '%c' S=%09lu TABLA_CORRUPTA",
        db, tabla_registros[db][0]);
  }
}

/*
 *
 * HASHES
 *
 */

/*
 *
 * db_actualiza_hash
 * algoritmo de calculo de hash extraído del ircuH, http://devel.irc-hispano.org
 *
 */
static inline void db_actualiza_hash(char *registro, char db)
{
  char tmpbuf[700];
  unsigned long k[4], x[2], v[2];
  char *p;

  memset(tmpbuf, 0, 500);
  strncpy(tmpbuf, registro, 500);

  while (strchr(tmpbuf, '\n'))
  {
    *(strchr(tmpbuf, '\n')) = '\0';
  }
  while (strchr(tmpbuf, '\r'))
  {
    *(strchr(tmpbuf, '\r')) = '\0';
  }

  p = tmpbuf;

  memset(k, 0, sizeof(unsigned long)*4);
  x[0] = tabla_hash[db][0];
  x[1] = tabla_hash[db][1];
  while (*p)
  {
    v[0] = ntohl(*p++);
    v[1] = ntohl(*p++);
    tea(v, k, x);
  }
  tabla_hash[db][0] = x[0];
  tabla_hash[db][1] = x[1];
}

static inline void db_almacena_hash(char db)
{
  int handle;
  char tmpbuf[100];
  char path[1024];
  char hash1[7], hash2[7];

  int tabla_version;

  if ((db >= BDD_START) && (db <= BDD_END))
  {
    tabla_version = 1;
  }
  else if ((db >= BDD2_START) && (db <= BDD2_END))
  {
    tabla_version = 2;
  }
  else
  {
    db_die("Error al almacenar hash (version desconocida)");
  }

  sprintf(path, "%s/hashes", DB_DIR);
  handle = open(path, O_WRONLY, S_IREAD|S_IWRITE);
  if (handle == -1)
  {
    char tabla;
    handle = open(path, O_WRONLY | O_CREAT, S_IREAD | S_IWRITE);
    if (handle == -1)
    {
      db_die("Error al almacenar hash (open)");
      return;
    }
    for (tabla=BDD_START; tabla <= BDD_END; tabla++)
    {
      sprintf(tmpbuf, "%c AAAAAAAAAAAA\n", tabla);
      write(handle, tmpbuf, 15);
    }
    for (tabla=BDD2_START; tabla <= BDD2_END; tabla++)
    {
      sprintf(tmpbuf, "%c AAAAAAAAAAAA\n", tabla);
      write(handle, tmpbuf, 15);
    }
  }

  if (tabla_version == 1)
  {
    if (lseek(handle, (15*(db-BDD_START)), SEEK_SET) == -1)
      db_die("Error al almacenar hash (lseek)");
  }
  else if (tabla_version == 2)
  {
    if (lseek(handle, (15*(BDD_END-BDD_START+1+(db-BDD2_START))), SEEK_SET) == -1)
    {
      db_die("Error al almacenar hash (lseek)");
    }
  }

  db_get_hash_str(db, hash1, hash2);
  sprintf(tmpbuf, "%c %s%s\n", db, hash1, hash2);
  if (write(handle, tmpbuf, 15) == -1)
  {
    db_die("Error al almacenar hash (write)");
  }
  close(handle);
}

static inline void db_get_hash_str(char db, char *dest1, char *dest2)
{
  inttobase64(dest1, tabla_hash[db][0], 6);
  inttobase64(dest2, tabla_hash[db][1], 6);
}

static inline void db_get_hash(char db, unsigned long *dest1, unsigned long *dest2, int tabla_version)
{
  int handle;
  char path[1024];
  char c;
  char readed[13];
  
  readed[12] = '\0';
  sprintf(path, "%s/hashes", DB_DIR);

  handle = open(path, O_RDONLY, S_IREAD | S_IWRITE);
  if (handle == -1)
  {
    *dest1 = *dest2 = 0;
    return;
  }
  if (tabla_version == 1)
  {
    if (lseek(handle, (15*(db-BDD_START))+2, SEEK_SET) == -1)
    {
      db_die("Error al leer hash (lseek)");
    }
  }
  else if (tabla_version == 2)
  {
    if (lseek(handle, (15*(BDD_END-BDD_START+1+(db-BDD2_START)))+2, SEEK_SET) == -1)
    {
      db_die("Error al leer hash (lseek)");
    }
  }

  read(handle, readed, 12);
  c = readed[6];
  readed[6] = '\0';
  *dest1 = base64toint(readed);
  readed[6] = c;
  *dest2 = base64toint(readed+6);
  close(handle);
}

static inline void db_tabla_comprueba_corrupcion(char db, int tabla_version)
{
  unsigned long hash1, hash2;
  db_get_hash(db, &hash1, &hash2, tabla_version);

  if (tabla_hash[db][0] != hash1 || tabla_hash[db][1] != hash2)
  {
    tabla_corrupta[db] = !0;
    borrar_db(db, tabla_version);
  }
  else
  {
    tabla_corrupta[db] = 0;
  }
}

inline int tabla_es_corrupta(char db)
{
  return ((tabla_corrupta[db] != 0) ? !0 : 0);
}






/*
 *
 * ACTIVIDAD de las tablas
 * Tablas que surten efecto nada más insertar el registro
 *
 */

/*
 * Canales activos
 */
static int tabla_activa_canales(char *clave, char *subclave, char *valor)
{
  struct Channel *chptr;
  struct db_reg *reg1;
  struct db2_reg *reg;
  char *botname;
  struct Membership *member;

  chptr = FindChannel(clave);
  if (!chptr)
  {
    return 0;
  }

  reg = db2_buscar_registro(BDD_CHANNELS, clave);

  if ((reg1 = db_buscar_registro(BDD_BOTS, BDD_BOTS_CHANSERV)) && (reg1->valor))
  {
    botname = reg1->valor;
  }
  else
  {
    botname = cli_name(&me);
  }

  /* En principio si un canal tiene alguna subclave en la tabla C, debe tener +r */
  if (!reg && (chptr->rhmode.mode & RHMODE_REGISTERED))
  {
    chptr->rhmode.mode &= ~RHMODE_REGISTERED;

    /* Enviamos el -r a nuestros usuarios dentro del canal */
    for (member = chptr->members; member; member = member->next_member)
    {
      if (!MyUser(member->user))
      {
        continue;
      }
      sendbotcmd(botname, CMD_MODE, member->user, "%H -r", chptr);
    }
    
    /* Eliminamos el fundador */
    chptr->founder = NULL;
    /* Si se ha borrado el canal de la base de datos, concluímos aquí */
    return;
  }
  
  else if (reg && !(chptr->rhmode.mode & RHMODE_REGISTERED))
  {
    struct Membership *member;
    chptr->rhmode.mode |= RHMODE_REGISTERED;

    for (member = chptr->members; member; member = member->next_member)
    {
      if (!MyUser(member->user))
      {
        continue;
      }
      sendbotcmd(botname, CMD_MODE, member->user, "%H +r", chptr);
    }
  }

  /* Y ahora comprobamos si hay cambios en los fundadores */
  if (subclave)
  {
  
    if (!strcasecmp(subclave+1, BDD_CHANNELS_FOUNDER))
    {
      struct Membership *member, *member2;
      struct _db2_valores_ *v = NULL;
      struct Client *acptr = NULL;
     
      member = member2 = NULL;

      /* Buscamos el subregistro de fundador */
      if (reg)
      {
        v = db2_buscar_en_registro(reg, BDD_CHANNELS_FOUNDER);
      }
      
      /* Buscamos la estructura que apunte al nuevo fundador si existe */
      if (v->valor)
      {
        acptr = FindUser(v->valor);
      }
    
      /* Buscamos el enlace en el canal del antiguo y nuevo fundador */
      if (chptr->founder)
      {
        member = find_member_link(chptr, chptr->founder);
      }
      if (acptr)
      {
        member2 = find_member_link(chptr, acptr);
      }
   
      /* Si hay un fundador actualmente y nos pasan uno nuevo, eliminamos al actual */
      if (member && (chptr->founder != NULL) && MyUser(chptr->founder) && (chptr->founder != acptr))
      {
        chptr->founder = NULL;
      }
        
      /* Seteamos como fundador al nuevo que nos han pasado */
      if (member2 && (acptr != NULL) && MyUser(acptr) && (chptr->founder != acptr))
      {
        chptr->founder = acptr;
      }
    }
  } /* if (subclave) */
}


/*
 * Raws activos
 */
static int tabla_activa_rawsdb(char *clave, char *valor)
{
  struct Client *acptr;

  assert(0 != clave);
  if (!((acptr = FindClient(clave)) && IsUser(acptr)))
    return;
    
  if (valor != NULL) {
    SetRawStatus(acptr);
    ircd_strncpy(cli_user(acptr)->rawline, valor, RAWLEN);
  } else {
    ClearRawStatus(acptr);
    cli_user(acptr)->rawline[0] = '\0';
  }
}

/*
 * Access activos
 */
static int tabla_activa_access(char *clave, char *valor)
{
}

/*
 * Vhosts activos
 */
static int tabla_activa_vhosts(char *clave, char *valor)
{
  struct Client *acptr;


  if (strcmp(clave, ".") == 0)
  {
    struct Client *cptr;

    /* Si cambiamos la clave de cifrado, hay que re-generar todas las ips virtuales */
    for (cptr = GlobalClientList; cptr; cptr = cli_next(cptr))
    {
      if (IsServer(cptr))
      {
        continue;
      }
      if (!cli_user(cptr))
      {
        continue;
      }
      cli_user(cptr)->virtualhost[0] = '\0';
    }

    return 0;
  }

  /* Reestablecemos su ip virtual */
  if ((acptr = FindClient(clave)))
  {
    make_virtualhost(acptr, 1);
  }
}


/*
 * Joins activos
 */
static int tabla_activa_joins(char *clave, char *valor)
{
  struct Channel *chptr;
  struct db_reg *reg;
  char *botname;

  if (!clave)
  {
    return 0;
  }

  chptr = FindChannel(clave);
  if (!chptr)
  {
    return 0;
  }
  
  if ((reg = db_buscar_registro(BDD_BOTS, BDD_BOTS_CHANSERV)) && (reg->valor))
  {
    botname = reg->valor;
  }
  else
  {
    botname = cli_name(&me);
  }

  if ((valor != NULL) && (atol(valor) > 0L) && !(chptr->rhmode.mode & RHMODE_HASJOINP))
  {
    struct Membership *member;

    for (member = chptr->members; member; member = member->next_member)
    {
      if (!MyUser(member->user))
      {
        continue;
      }
      sendbotcmd(botname, CMD_MODE, member->user, "%H +j", chptr);
    }
    chptr->rhmode.mode |= RHMODE_HASJOINP;
    return 0;
  }
  if (((valor == NULL) || (atol(valor) == 0L)) && (chptr->rhmode.mode & RHMODE_HASJOINP))
  {
    struct Membership *member;

    for (member = chptr->members; member; member = member->next_member)
    {
      if (!MyUser(member->user))
      {
        continue;
      }
      sendbotcmd(botname, CMD_MODE, member->user, "%H -j", chptr);
    }
    chptr->rhmode.mode &= ~RHMODE_HASJOINP;
    return 0;
  }
}

/*
 * Flags activos
 */
static int tabla_activa_flags(char *clave, char *valor)
{
  struct Client *acptr;
  unsigned int old_flags;
    
  assert(0 != clave);
    
  /* Para que surta efecto la actividad del registro la clave debe ser un nick
  conectado y marcado como usuario */
  if (!((acptr = FindClient(clave)) && IsUser(acptr)))
  {
    return;
  }
    
  if (valor != NULL)
  {
    cli_user(acptr)->dbflags = atoi(valor);
  }
  else
  {
    cli_user(acptr)->dbflags = 0;
  }

  /* Ajustamos los nuevos modos convenientemente */
  old_flags = cli_rhflags(acptr);
  cli_rhflags(acptr) |= (RHFLAGS_COADM | RHFLAGS_ADM | RHFLAGS_MODERA | RHFLAGS_HELPOP | RHFLAGS_BOT | RHFLAGS_USERBOT);
  comprueba_privilegios(acptr);
  if (cli_rhflags(acptr) != old_flags)
  {
    send_umode_out(acptr, acptr, cli_flags(acptr), old_flags, 0);
  }
}

/*
 * Gestion de registro y suspensiones
 */
static int tabla_activa_users(char *clave, char *valor)
{
  struct Client *acptr;
  unsigned int old_flags;
  struct db_reg *reg;
  char c;
  int nick_suspendido = 0;
  int nick_forbid = 0;
  
  assert(0 != clave);
    
  /* Para que surta efecto la actividad del registro la clave debe ser un nick
  conectado y marcado como usuario */
  if (!((acptr = FindClient(clave)) && IsUser(acptr)))
  {
    return;
  }
    
  old_flags = cli_rhflags(acptr);
  cli_user(acptr)->dbflags = 0;

  if (valor != NULL)
  {
    c = valor[strlen(valor) - 1];
    if (c == '+')
      nick_suspendido = 1;
    else if (c == '*')
      nick_forbid = 1;

    /* Si el nick esta suspendido ponemos el modo +S */
    if (nick_suspendido) 
    {
        cli_rhflags(acptr) |= RHFLAGS_SUSPENDED;
    }
    else if (nick_forbid) /* El nick está prohibido hacemos rename */
    {
        /*IMPLEMENTAR FUNCION*/
        return;
    }
    else /* El nick se registra en la BDD, se reactiva o cambia clave */
    {
        cli_rhflags(acptr) &= ~RHFLAGS_SUSPENDED;
        cli_rhflags(acptr) |= (RHFLAGS_REGNICK | RHFLAGS_COADM | RHFLAGS_ADM | RHFLAGS_MODERA | RHFLAGS_HELPOP | RHFLAGS_BOT | RHFLAGS_USERBOT);
        if (reg = db_buscar_registro(BDD_FLAGS, cli_name(acptr)))
           cli_user(acptr)->dbflags = atoi(reg->valor);
    }
  }
  else
  {
    /* Usuario que se desregistra perdemos los modos */
    cli_rhflags(acptr) &= ~(RHFLAGS_REGNICK | RHFLAGS_SUSPENDED);
  }

  /* Comprobamos privilegios y cambiamos modos si procede */
  comprueba_privilegios(acptr);
  if (cli_rhflags(acptr) != old_flags)
  {
    send_umode_out(acptr, acptr, cli_flags(acptr), old_flags, 0);
  }
}

/*
 * Gestion de la tabla de configuracion global de red
 */
static int tabla_activa_config(char *clave, char *valor)
{
}


/*
 * Iterador de tablas
 *
 */

/* Inicializa un iterador a una tabla versión 1 */
struct db_reg *db_iterador_init(char tabla)
{
  /* No se puede hacer un iterador de tablas que no existen */
  if (tabla < BDD_START || tabla > BDD_END)
  {
    return NULL;
  }

  db_iterador_tabla = tabla;
  db_iterador_registro = NULL;
  db_iterador_hash = 0;
  db_iterador_hash_len = tabla_residente[tabla];
    
  return db_iterador_first();
}

/* Retorna el primer registro de una tabla versión 1 */
static struct db_reg *db_iterador_first(void)
{
  /* Debemos buscar el primer bucket con datos */
  while (db_iterador_hash < db_iterador_hash_len)
  {
    db_iterador_registro = primer_db[db_iterador_tabla][db_iterador_hash];
    if (NULL != db_iterador_registro)
    {
      db_iterador_hash_len--;
      return db_iterador_registro;
    }
    db_iterador_hash++;
  }
  
  db_iterador_registro = NULL;
  db_iterador_hash = 0;
  return NULL;
}

/* Retorna el siguiente registro de una tabla versión 1 */
struct db_reg *db_iterador_next(void)
{
  /* Pasamos al siguiente registro */
  if (NULL != db_iterador_registro)
  {
    db_iterador_registro = db_iterador_registro->next;
    
    /* Si hay siguiente, retornamos su valor */
    if (NULL != db_iterador_registro)
    {
      return db_iterador_registro;
    }
    
  }

  /* Buscamos el siguiente bucket con registros */
  while (db_iterador_hash < db_iterador_hash_len)
  {
    db_iterador_registro = primer_db[db_iterador_tabla][++db_iterador_hash];
    
    /* Hemos encontrado un bucket con datos */
    if (db_iterador_registro != NULL)
    {
      return db_iterador_registro;
    }
  }
  
  /* Si llegamos aquí, significa que hemos finalizado el recorrido, así que
     volvemos al principio */
  db_iterador_registro = NULL;
  db_iterador_hash = 0;

  return NULL;
}

/* Inicializa un iterador a una tabla versión 2 */
struct db2_reg *db2_iterador_init(char tabla)
{
    /* No se puede hacer un iterador de tablas que no existen */
  if (tabla < BDD2_START || tabla > BDD2_END)
  {
    return NULL;
  }

  db_iterador_tabla = tabla;
  db2_iterador_registro = NULL;
  db_iterador_hash = 0;
  db_iterador_hash_len = tabla_residente[tabla];
    
  return db2_iterador_first();
}

/* Retorna el primer registro de una tabla versión 1 */
static struct db2_reg *db2_iterador_first(void)
{
  /* Debemos buscar el primer bucket con datos */
  while (db_iterador_hash < db_iterador_hash_len)
  {
    db2_iterador_registro = primer_db2[db_iterador_tabla][db_iterador_hash];
    if (NULL != db2_iterador_registro)
    {
      db_iterador_hash_len--;
      return db2_iterador_registro;
    }
    db_iterador_hash++;
  }
  
  db2_iterador_registro = NULL;
  db_iterador_hash = 0;
  return NULL;
}

/* Retorna el siguiente registro de una tabla versión 2 */
struct db2_reg *db2_iterador_next(void)
{
  /* Pasamos al siguiente registro */
  if (NULL != db2_iterador_registro)
  {
    db2_iterador_registro = db2_iterador_registro->next;
    
    /* Si hay siguiente, retornamos su valor */
    if (NULL != db2_iterador_registro)
    {
      return db2_iterador_registro;
    }
    
  }

  /* Buscamos el siguiente bucket con registros */
  while (db_iterador_hash < db_iterador_hash_len)
  {
    db2_iterador_registro = primer_db2[db_iterador_tabla][++db_iterador_hash];
    
    /* Hemos encontrado un bucket con datos */
    if (db2_iterador_registro != NULL)
    {
      return db2_iterador_registro;
    }
  }
  
  /* Si llegamos aquí, significa que hemos finalizado el recorrido, así que
     volvemos al principio */
  db2_iterador_registro = NULL;
  db_iterador_hash = 0;

  return NULL;
}


/*
 * m_dbq
 * RyDeN - 12 Junio 2003
 *
 */

extern unsigned int lastNNServer;
extern struct Client *server_list[];
CMD_FUNC(m_dbq)
{
  char      *servidor;
  char      *clave;
  char      *subclave = NULL;
  char      tabla;
  struct db_reg    *reg;
  struct db2_reg  *reg2;
  struct _db2_valores_   *v;
  int      busca_hash = 0;

  if (!IsServer(sptr) && !IsOper(sptr) && !es_representante(sptr))
  {
    return send_reply(sptr, ERR_NOPRIVILEGES);
  }

  if (parc < 3)
  {
    sendcmdto_one(&me, CMD_NOTICE, cptr, "%C :Sintaxis: DBQ [servidor] <tabla> <clave> {subclave}", sptr);
    return need_more_params(sptr, "DBQ");
  }

  if (parc == 3)
  {
    servidor = NULL;

    /*
     * RyDeN - 16 Mayo 2004
     *
     * Implementamos el DBQ de HASH
     *
     */
    if (strcasecmp(parv[1], "HASH") == 0)
    {
      busca_hash = !0;
      tabla = *parv[2];
    }
    else
    {
      tabla = *parv[1];
      clave = parv[2];
    }

    if (tabla >= BDD2_START && tabla <= BDD2_END)
    {
      sendcmdto_one(&me, CMD_NOTICE, cptr, "%C :Sintaxis: DBQ [servidor] <tabla> <clave> {subclave}", sptr);
      return need_more_params(sptr, "DBQ");
    }
  }
  else
  {
    if (strcasecmp(parv[2], "HASH") == 0)
    {
      busca_hash = !0;
      tabla = *parv[3];
    }
    else
    {
      tabla = *parv[1];
    }

    if (!busca_hash && tabla >= BDD2_START && tabla <= BDD2_END)
    {
      servidor = NULL;
      clave = parv[2];

      if (parc == 4)
      {
        subclave = parv[3];
      }
      else
      {
        sendcmdto_one(&me, CMD_NOTICE, cptr, "%C :Sintaxis: DBQ [servidor] <tabla> <clave> {subclave}", sptr);
        return need_more_params(sptr, "DBQ");
      }
    }
    else
    {
      servidor = parv[1];
      if (!busca_hash)
      {
        tabla = *parv[2];
        clave = parv[3];
      }

      if (!busca_hash && tabla >= BDD2_START && tabla <= BDD2_END)
      {
        if (parc == 5)
        {
          subclave = parv[4];
        }
        else
        {
          sendcmdto_one(&me, CMD_NOTICE, cptr, "%C :Sintaxis: DBQ [servidor] <tabla> <clave> {subclave}", sptr);
          return need_more_params(sptr, "DBQ");
        }
      }
    }
  }

  if (servidor != NULL)
  {
    if (!strcmp(servidor, "*"))
    {
      if (busca_hash)
      {
        sendcmdto_serv_butone(sptr, CMD_DBQ, NULL, "* HASH %c", tabla);
      }
      else
      {
        sendcmdto_serv_butone(sptr, CMD_DBQ, NULL, "* %c %s", tabla, clave);
      }
    }
    else
    {
      struct Client *acptr;
      int i;
      int a_mi = 0;
      int a_alguien = 0;

      collapse(servidor);
      /* Enviamos el DBQ a todos los servidores que coinciden con el token */
      for (i = 0; i < lastNNServer; i++)
      {
        if ((acptr = server_list[i]) && (!match(servidor, cli_name(acptr))))
        {
          if (acptr == &me)
          {
            a_mi = a_alguien = 1;
            continue;
          }
          a_alguien = 1;

          if (busca_hash)
          {
            sendcmdto_one(sptr, CMD_DBQ, acptr, "%s HASH %c", servidor, tabla);
          }
          else
          {
            if (subclave)
            {
              sendcmdto_one(sptr, CMD_DBQ, acptr, "%s %c %s %s", servidor, tabla, clave, subclave);
            }
            else
            {
              sendcmdto_one(sptr, CMD_DBQ, acptr, "%s %c %s", servidor, tabla, clave);
            }
          }
        }
      }

      if (a_alguien == 0)
      {
        return send_reply(sptr, ERR_NOSUCHSERVER, servidor);
      }

      if (a_mi == 0)
      {
        return 0;
      }
    }
  }

  if (busca_hash)
  {
    char hashtabla[13];
    inttobase64(hashtabla, tabla_hash[tabla][0], 6);
    inttobase64(hashtabla+6, tabla_hash[tabla][1], 6);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :DBQ Tabla='%c' HASH='%s'",
        sptr, tabla, hashtabla);
    return 0;
  }

  if (tabla_es_residente(tabla) == 0)
  {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :DBQ ERROR Tabla='%c' NO_RESIDENTE",
        sptr, tabla);
    return 0;
  }
  if (tabla_es_corrupta(tabla))
  {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :DBQ ERROR Tabla='%c' CORRUPTA",
        sptr, tabla);
    return 0;
  }

  if (subclave)
  {
    if (!(reg2 = db2_buscar_registro(tabla, clave)) || !(reg2->valor))
    {
      sendcmdto_one(&me, CMD_NOTICE, sptr,
          "%C :DBQ ERROR Tabla='%c' Clave='%s' REGISTRO_NO_ENCONTRADO",
          sptr, tabla, clave
          );
      return 0;
    }

    if ((v = db2_buscar_en_registro(reg2, subclave)) == NULL)
    {
      sendcmdto_one(&me, CMD_NOTICE, sptr,
            "%C :DBQ ERROR Tabla='%c' Clave='%s' SubClave='%s' SUBCLAVE_NO_ENCONTRADA",
            sptr, tabla, clave, subclave
            );
      return 0;
    }
  }
  else
  {
    if (!(reg = db_buscar_registro(tabla, clave)) || !(reg->valor))
    {
      sendcmdto_one(&me, CMD_NOTICE, sptr,
            "%C :DBQ ERROR Tabla='%c' Clave='%s' REGISTRO_NO_ENCONTRADO",
            sptr, tabla, clave
            );
      return 0;
    }
  }

  if (subclave)
  {
    sendcmdto_one(&me, CMD_NOTICE, sptr,
        "%C :DBQ OK Tabla='%c' Clave='%s' SubClave='%s' Valor='%s'",
        sptr, tabla, reg2->clave, v->clave, v->valor
        );
  }
  else
  {
    sendcmdto_one(&me, CMD_NOTICE, sptr,
        "%C :DBQ OK Tabla='%c' Clave='%s' Valor='%s'",
        sptr, tabla, reg->clave, reg->valor
        );
  }
  return 0;
}
