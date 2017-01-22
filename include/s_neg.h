#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

/* s_neg.h
	Fichero cabecera necesario para la negociación de enlaces

  RyDeN - Alberto Alonso - ryden@redhispana.org
  23 Diciembre 2003
*/

#define NEGOCIACION_ZLIB_IN		0x001
#define NEGOCIACION_ZLIB_OUT	0x002
#define NEGOCIACION_ZLIB_SPEC	0x004
#define NEGOCIACION_RC4_IN		0x008
#define NEGOCIACION_RC4_OUT		0x010
#define NEGOCIACION_RC4_SPEC	0x020
#define NEGOCIACION_RC4_WAITING 0x040
#define NEGOCIACION_TOKEN_OUT	0x080
#define NEGOCIACION_TOKEN_SPEC	0x100

#define NEGOCIACION_IN		0x01
#define NEGOCIACION_OUT		0x02
#define NEGOCIACION_ESPEC	0x04

#define NEG_REQ		"REQ"
#define NEG_ACK		"ACK"
#define P_NEG(x) void (x)(struct Client *cptr, int tipo_negociacion)

/* Estructuras */
struct Configs {
	char *name;
	unsigned int flag_in;		/* Negociaciones entrantes aceptadas remotamente */
	unsigned int flag_out;		/* Negociaciones salientes aceptadas localmente */
	unsigned int flag_spec;		/* Negociaciones que serán aceptadas */
	void (*funcion_procesado)(struct Client *cptr, int tipo_negociacion);
};
extern struct Configs configs[];

/* Funciones generales */
void envia_negociaciones(struct Client *cptr);
void acepta_negociaciones(struct Client *cptr, unsigned int old);

/* Funciones propias de cada negociacion */
P_NEG(inicia_zlib);
P_NEG(inicia_rc4);

