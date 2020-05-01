#include "../ssl_md5.h"

void	determin_hash_func(char *str, t_ssl *s)
{
	if (!ft_strcmp(str, "md5"))
	{
		ft_memcpy(s->hash_name, "MD5", 4);
		s->hash_func = &md5_funct;
	}
	else if (!ft_strcmp(str, "sha256"))
	{
		ft_memcpy(s->hash_name, "SHA256", 7);
		s->hash_func = &sha256_funct;
	}
	else
		quit("invalid hash function\n");
}

void	parsing(char **av, t_ssl *s)
{
	int i;

	if (!av[1])
		quit("no hash function selected\n");
	ft_bzero(s, sizeof(t_ssl));
	determin_hash_func(av[1], s);
	i = 1;
	while (av[++i])
	{
		if (!ft_strcmp(av[i], "-p"))
			s->p = 1;
		else if (!ft_strcmp(av[i], "-r"))
			s->r = 1;
		else if (!ft_strcmp(av[i], "-q"))
			s->q = 1;
		else if (!ft_strcmp(av[i], "-s") && !s->s)
			!(s->s = av[++i]) ? quit("option s has no string\n") : 0;
		else if (ft_strcmp(av[i], "-s"))
			!s->file ? s->file = av[i] : 0;
	}
}
