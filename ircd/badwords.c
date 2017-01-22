/*
 * IRC - Internet Relay Chat, ircd/badwords.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Co Center
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
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "channel.h"
#include "client.h"
#include "ircd_alloc.h"
#include "s_bdd.h"
#include "s_debug.h"

/*
 * RyDeN - 21 Junio 2003
 * MyStrncasestr
 * Busca en un texto una cadena de texto de ancho length sin importar el case
 * De momento necesario para el process_badwords
 */
char *MyStrncasestr(char *where, char *str, unsigned int length)
{
	char *ptr = where;

	while (*ptr) {
		if (strncasecmp(ptr, str, length) == 0)
			return ptr;
		ptr++;
	}
	return (char *)NULL;
}

/*
 * RyDeN - 21 Junio 2003
 * strip_badwords
 * Parsea un texto en búsca de palabras prohibidas para sustituirlas
 *
 */
char *process_badwords(const char *text, int flags)
{
	char *ptr, *ptr2, *ptr3, *ptrf;
	struct db_reg *reg, *reg2;
	int i = 0, length, reg_len, len;
	static char *temp_buffer = NULL;
	static unsigned long last_length;
	char *texto = temp_buffer, *texto2 = texto;
	char *badword_str;
	int badword_length;

	if (temp_buffer == NULL)
	{
		last_length = BUFSIZE * 100;	/* RyDeN -- Espero que sea suficiente para
										   no tener que hacer realloc :) */
		temp_buffer = (char *)malloc(sizeof(char)*last_length);
		texto2 = texto = temp_buffer;
	}
	
	/* Si no hay palabras prohibidas, es inutil parsear la frase */
	reg = db_iterador_init(BDD_BADWORDS);
	if (reg == NULL)
	{
		return NULL;
	}

	strcpy(temp_buffer, text);
	len = strlen(text)+1;
	
	if (!(reg2 = db_buscar_registro(BDD_BADWORDS, ".")) || !(reg2->valor))
		badword_str = "(censurado)";
	else
		badword_str = reg2->valor;
	badword_length = strlen(badword_str);

	for (; reg != NULL; reg = db_iterador_next())
	{
		if (!(atoi(reg->valor) & flags))
			continue;
		
		reg_len = strlen(reg->clave);
		/* Buscamos la palabra prohibida en el texto */
		while ((ptrf = MyStrncasestr(texto2, reg->clave, reg_len)))
        {
			if ((flags == BADWORDS_QUERY) || (flags == BADWORDS_QUITMSG))
				return (char*)0x1;
			/* Desplazamos el texto hacia la izquierda o derecha, según convenga */
			length = badword_length - reg_len;
			texto2 = ptrf + badword_length;

			len += length;
			if (length > 0) {
				if (len > last_length)
				{
					/* realloc */
					int diff = ptrf - texto;
					last_length <<= 1;
					last_length += len; /* Nos curamos en salud, aunque es extraño que ocurra */
					temp_buffer = (char *)realloc(temp_buffer, sizeof(char)*last_length);

					/* A restaurar variables */
					texto = temp_buffer;
					ptrf = texto + diff;
					texto2 = ptrf + badword_length;
				}
				/* Situamos ptr en el lugar en el que comenzará la lectura */
				ptr = texto + strlen(texto);
				/* Situamos ptr2 en el lugar en el que se terminará la escritura */
				ptr2 = ptrf + reg_len + length;
				/* Situamos ptr3 en el lugar donde comenzará la escritura */
				ptr3 = ptr + length;

				/* Copiamos el texto, desplazándolo */
				while (ptr3 >= ptr2)
					*ptr3-- = *ptr--;
			} else {
				ptr = ptrf + reg_len;
				ptr2 = ptr + length;
				ptr3 = texto + strlen(texto);

				while (ptr <= ptr3)
					*ptr2++ = *ptr++;
			}

			/* Sustituímos el hueco por la palabra badword */
			ptr = badword_str;
			ptr2 = ptrf + badword_length - 1;
			while (ptrf <= ptr2)
				*ptrf++ = *ptr++;

		}
		texto2 = texto;
		i++;
	}
	if ((flags == BADWORDS_QUERY) || (flags == BADWORDS_QUITMSG))
		return NULL;
	return temp_buffer;
}
