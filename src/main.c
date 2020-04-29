#include "../ssl_md5.h"

void	quit(char *str)
{
	ft_printf("%s", str);
	exit(0);
}

void	aff_options(t_ssl *s)
{
	ft_printf("{\ns: %s\np: %d\nq: %d\nr: %d\nfile: %s\nhash func: %d\n}\n",
	s->s, s->p, s->q, s->r, s->file, s->hash_func);
}

int		main(int ac, char **av)
{
	t_ssl	s;
	int		n;

	n = 1;
	little_endian = *(char*)&n;
	parsing(av, &s);
	hashing(&s);
	return 0;
}
