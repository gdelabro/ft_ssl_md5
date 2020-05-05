#ifndef SSL_H
# define SSL_H

# include <unistd.h>
# include <stdlib.h>
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

typedef struct	s_md5
{
	int				a0;
	int				b0;
	int				c0;
	int				d0;
	unsigned int	a;
	unsigned int	b;
	unsigned int	c;
	unsigned int	d;
	char			*msg;
	int				nb_grps;
	int				q;
	size_t			size;
	int				grp;
	int				i;
	unsigned int	*m;
	int				f;
	int				g;
}				t_md5;

typedef struct	s_sha256
{
	unsigned int	w[64];
	int				a0;
	int				b0;
	int				c0;
	int				d0;
	int				e0;
	int				f0;
	int				g0;
	int				h0;
	int				t1;
	int				t2;
	char			*msg;
	int				nb_grps;
	size_t			size;
	int				grp;
	int				i;
	unsigned int	*m;
	unsigned int	a;
	unsigned int	b;
	unsigned int	c;
	unsigned int	d;
	unsigned int	e;
	unsigned int	f;
	unsigned int	g;
	unsigned int	h;
}				t_sha256;

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
	int		len;
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
