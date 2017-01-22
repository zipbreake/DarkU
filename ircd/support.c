/*
 * IRC - Internet Relay Chat, common/support.c
 * Copyright (C) 1990, 1991 Armin Gruner
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
 * $Id: support.c,v 1.1.1.1 2006/05/27 13:54:40 zipbreake Exp $
 */
#include "config.h"

#include "support.h"
#include "fileio.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_snprintf.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "send.h"
#include "sys.h"

#include <signal.h>   /* kill */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/*
   RyDeN - Es necesario comprobar si es una mascara de IP, especifico para los
   glines, ya que las glines a ips tipo 127.1* no deben tener un ipmask
*/
int gline_check_if_ipmask(const char *mask)
{
  int has_digit = 0;
  int digit_in_byte = 0;
  const char *p;
  
  for (p = mask; *p; ++p)
  {
    if (*p != '*' &&  *p != '?' && *p != '.' && *p != '/')
    {
      if (!IsDigit(*p))
        return 0;

      digit_in_byte = !0;
      has_digit = -1;
    }
    else
    {
      if (*p == '.')
      {
        digit_in_byte = 0;
        continue;
      }
      
      if (*p == '*' || *p == '?')
      {
        /* Máscara tipo *67* */
        if (digit_in_byte || IsDigit(*(p + 1)))
          return 0;
      }

    } /* else */
  } /* for (p = mask; *p; ++p) */
  
  return has_digit;
}

int check_if_ipmask(const char *mask)
{
  int has_digit = 0;
  const char *p;

  for (p = mask; *p; ++p)
    if (*p != '*' && *p != '?' && *p != '.' && *p != '/')
    {
      if (!IsDigit(*p))
        return 0;
      has_digit = -1;
    }

  return has_digit;
}

/* Moved from logf() in whocmds.c to here. Modified a 
 * bit and used for most logging now.
 *  -Ghostwolf 12-Jul-99
 */

extern void write_log(const char *filename, const char *pattern, ...)
{
  FBFILE *logfile;
  va_list vl;
  static char logbuf[1024];

  logfile = fbopen(filename, "a");

  if (logfile)
  {
    va_start(vl, pattern);
    ircd_vsnprintf(0, logbuf, sizeof(logbuf) - 1, pattern, vl);
    va_end(vl);

    fbputs(logbuf, logfile);
    fbclose(logfile);
  }
}
