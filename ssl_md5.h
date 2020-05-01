#ifndef SSL_H
# define SSL_H

# include <unistd.h>
# include <stdlib.h>
# include <time.h>
# include <sys/types.h>
# include <sys/stat.h>
# include "ft_printf/ft_printf.h"

# define ROTR(x, nb) (((x) >> nb) | ((x) << (32 - nb)))
# define ROTL(x, nb) (((x) << nb) | ((x) >> (32 - nb)))
# define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
# define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
# define E0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
# define E1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
# define O0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
# define O1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

int				little_endian;

typedef struct s_ssl t_ssl;

typedef struct	s_ssl
{
	int		p;
	int		q;
	int		r;
	char	*s;
	char	*file;
	char	*file_content;
	char	*input;
	void	(*hash_func)(char *, t_ssl *);
	int		size_hash;
	int		hash[8];
	char	hash_name[32];
}				t_ssl;

void			quit(char *str);

void			parsing(char **av, t_ssl *s);

void			hashing(t_ssl *s);

void			md5_funct(char *message, t_ssl *ssl);
void			sha256_funct(char *message, t_ssl *ssl);
unsigned int	switch_endian(unsigned int nb);
unsigned int	rotateleft(unsigned int nb, unsigned int rot);
unsigned int	rotateright(unsigned int nb, unsigned int rot);

#endif
