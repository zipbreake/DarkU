#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* RC4
	Encriptación servidor <=> servidor
	Código fuente extraído del BAHAMUT de DALnet
*/

typedef char RC4BYTE;
typedef int RC4DWORD;

struct rc4_state
{
    RC4BYTE mstate[256];
    RC4BYTE x;
    RC4BYTE y;
};

/*The first parameter was an unsigned char. It has been changed to a char
to avoid the "differ in signedness" warning.
*/
void *rc4_initstate(char *key, int keylen)
{
   RC4DWORD i;
   RC4BYTE tmp, idx1;
	
   /*idx2 has been redefined from a RC4BYTE to a RC4DWORD because idx2 can have
	a value higher than 255.*/
   RC4DWORD	idx2;
   struct rc4_state *rc4;
   
   if(sizeof(RC4BYTE) != 1)  abort(); /* MUST BE 1 BYTE! */
   if(sizeof(RC4DWORD) != 4) abort(); /* MUST BE 4 BYTES! */
   
   rc4 = (struct rc4_state *) malloc(sizeof(struct rc4_state));
   memset(rc4, 0, sizeof(struct rc4_state));
   
   for(i = 0; i < 256; i++) /* initialize our state array */
       rc4->mstate[i] = (RC4BYTE) i;
   
   for(i = 0, idx1 = idx2 = 0; i < 256; i++)
   {
       idx2 = (key[idx1++] + rc4->mstate[i] + idx2);
       
       if(idx2 > 255)
	   abort(); /* let the braindead compiler die here
		     * instead of causing memleaks */
       
      tmp = rc4->mstate[i];
      rc4->mstate[i] = rc4->mstate[idx2];
      rc4->mstate[idx2] = tmp;
      
      if(idx1 >= keylen)
	  idx1 = 0;
   }
   
   return (void *) rc4;
}

/*The second parameter was an unsigned char. It has been changed to a char
to avoid the "differ in signedness" warning.
*/
void rc4_process_stream(void *rc4_context, char *istring,
			int stringlen)
{
    struct rc4_state *rc4 = (struct rc4_state *) rc4_context;
    RC4BYTE *s = rc4->mstate;
    RC4DWORD x = rc4->x, y = rc4->y;
    
    while(stringlen--)
    {
	RC4DWORD a, b;
	
	x = (x+1) & 0xFF;
	a = s[x];
	y = (y+a) & 0xFF;
	b = s[y];
	s[x] = b;
	s[y] = a;
	*istring++ ^= s[(a + b) & 0xFF];
    }
    
    rc4->x = (RC4BYTE) x;
    rc4->y = (RC4BYTE) y;
}

void rc4_process_stream_to_buf(void *rc4_context, 
			       const unsigned char *istring, 
                               unsigned char *ostring, unsigned int stringlen)
{
    struct rc4_state *rc4 = (struct rc4_state *) rc4_context;
    RC4BYTE *s = rc4->mstate;
    RC4DWORD x = rc4->x, y = rc4->y;
    
    while(stringlen--)
    {
	RC4DWORD a, b;
	
	x = (x+1) & 0xFF;
	a = s[x];
	y = (y+a) & 0xFF;
	b = s[y];
	s[x] = b;
	s[y] = a;
	*ostring++ = *istring++ ^ s[(a + b) & 0xFF];
    }
    
    rc4->x = (RC4BYTE) x;
    rc4->y = (RC4BYTE) y;
}

void rc4_destroystate(void *a)
{
    memset(a, 0, sizeof(struct rc4_state));
    free(a);
}
