#include "../ssl_md5.h"

void	quit(char *str)
{
	ft_printf("ft_ssl: %s\nStandard commands:\nMessage Digest Commands:\n\
md5\nsha256\nsha224\n\nCipher Commands:\n", str);
	exit(0);
}

int		main(int ac, char **av)
{
	t_ssl	s;
	int		n;

	(void)ac;
	n = 1;
	s.little_endian = *(char*)&n;
	parsing(av, &s);
	hashing(&s);
	return 0;
}
