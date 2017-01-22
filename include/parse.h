/*
 * parse.h
 *
 * $Id: parse.h,v 1.1.1.1 2006/05/27 13:55:06 zipbreake Exp $
 */
#ifndef INCLUDED_parse_h
#define INCLUDED_parse_h

struct Client;

/*
 * Prototypes
 */

extern int parse_client(struct Client *cptr, char *buffer, char *bufend);
extern int parse_server(struct Client *cptr, char *buffer, char *bufend);
extern void initmsgtree(void);

#endif /* INCLUDED_parse_h */
