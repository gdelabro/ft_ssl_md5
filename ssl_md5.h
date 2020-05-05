#ifndef SSL_H
# define SSL_H

# include <unistd.h>
# include <stdlib.h>
# include <time.h>
# include <sys/types.h>
# include <sys/stat.h>
# include "ft_printf/ft_printf.h"

# define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
# define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
# define E0(x) (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22))
# define E1(x) (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25))
# define O0(x) (rotr(x, 7) ^ rotr(x, 18) ^ ((x) >> 3))
# define O1(x) (rotr(x, 17) ^ rotr(x, 19) ^ ((x) >> 10))

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
unsigned int	rotl(unsigned int nb, unsigned int rot);
unsigned int	rotr(unsigned int nb, unsigned int rot);


#endif
