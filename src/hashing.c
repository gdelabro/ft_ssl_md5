#include "../ssl_md5.h"

void	print_hash(t_ssl *s)
{
	int i;

	i = -1;
	while (++i < s->size_hash)
		ft_printf("%.8x", s->hash[i]);
}

void	fill_file_content(t_ssl *s)
{
	int				fd;
	struct stat		st;
	char			buf[501];
	char			*tmp;
	int				i;

	s->file_content = NULL;
	fd = open(s->file, O_RDONLY);
	if (fd <= 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
		return ;
	while ((i = read(fd, buf, 500)) > 0)
	{
		buf[i] = 0;
		tmp = s->file_content;
		s->file_content = ft_strjoin(s->file_content, buf);
		free(tmp);
	}
	if (!i && !s->file_content)
		s->file_content = ft_strdup("");
}

void	hashing(t_ssl *s)
{
	char	buf[501];
	int		i;
	char	*tmp;

	s->input = NULL;
	while ((s->p || (!s->file && !s->s)) && (i = read(0, buf, 500)))
	{
		buf[i] = 0;
		tmp = s->input;
		s->input = ft_strjoin(s->input, buf);
		free(tmp);
	}
	if (s->input && ft_strcmp(s->input, ""))
	{
		s->hash_func(s->input ? s->input : "", s);
		s->p ? ft_printf("%s", s->input) : 0;
		s->p && s->input[ft_strlen(s->input) - 1] != '\n' ? ft_printf("\n") : 0;
		print_hash(s);
		ft_printf("\n");
		ft_strdel(&s->input);
	}
	if (s->s)
	{
		s->hash_func(s->s, s);
		!s->q && !s->r ? ft_printf("%s (\"%s\") = ", s->hash_name, s->s) : 0;
		print_hash(s);
		s->r && !s->q ? ft_printf(" \"%s\"", s->s) : 0;
		ft_printf("\n");
	}
	if (s->file)
	{
		fill_file_content(s);
		if (!s->file_content)
			ft_printf("can't open/read %s\n", s->file);
		else
		{
			s->hash_func(s->file_content, s);
			!s->q && !s->r ? ft_printf("%s (%s) = ", s->hash_name, s->file) : 0;
			print_hash(s);
			s->r && !s->q ? ft_printf(" %s", s->file) : 0;
			ft_printf("\n");
			ft_strdel(&s->file_content);
		}
	}
}
