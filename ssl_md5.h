#ifndef SSL_H
# define SSL_H

#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "ft_printf/ft_printf.h"

int				little_endian;

typedef struct	s_ssl
{
	int		p;
	int		q;
	int		r;
	char	*s;
	char	*file;
	char	*file_content;
	char	*input;
	int		hash_func;
	int		size_hash;
	int		hash[8];
}				t_ssl;

void	quit(char *str);

void	parsing(char **av, t_ssl *s);

void	hashing(t_ssl *s);

void	md5_funct(char *message, t_ssl *ssl);

#endif
