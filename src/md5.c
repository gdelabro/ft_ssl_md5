#include "../ssl_md5.h"

void			md5_funct(char *message, t_ssl *ssl)
{
	int s[64] = {7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
				5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
				4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
				6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21};
	int k[64] = {	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
					0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
					0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
					0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
					0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
					0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
					0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
					0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
					0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
					0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
					0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
					0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
					0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
					0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
					0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
					0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
	int		a0 = 0x67452301;
	int		b0 = 0xefcdab89;
	int		c0 = 0x98badcfe;
	int		d0 = 0x10325476;
	char	*msg;
	int		nb_grps;
	int		q;
	size_t	size;
	int		grp;
	int		i;

	nb_grps = 1 + (ft_strlen(message) + 8) / 64;
	if (!(msg = malloc(64 * nb_grps)))
		quit("malloc failed\n");
	ft_bzero(msg, 64 * nb_grps);
	memcpy(msg, message, ft_strlen(message));
	size = ft_strlen(message) * 8;
	msg[ft_strlen(message)] = 0x80;
	memcpy(msg + (64 * nb_grps) - 8, &size, 8);

	grp = -1;
	while (++grp < nb_grps)
	{
		unsigned int *M = (int*)(msg + grp * 64);
		unsigned int A = a0;
		unsigned int B = b0;
		unsigned int C = c0;
		unsigned int D = d0;
		i = -1;
		while (++i < 64)
		{
			int f;
			int g;
			
			if (i / 16 == 0)
			{
				f = (B & C) | (~B & D);
				g = i;
			}
			else if (i / 16 == 1)
			{
				f = (D & B) | (~D & C);
				g = (5 * i + 1) % 16;
			}
			else if (i / 16 == 2)
			{
				f = B ^ C ^ D;
				g = (3 * i + 5) % 16;
			}
			else if (i / 16 == 3)
			{
				f = C ^ (B | ~D);
				g = (7 * i) % 16;
			}
			f = f + A + k[i] + M[g];
			A = D;
			D = C;
			C = B;
			B = B + rotl(f, s[i]);
		}
		a0 += A;
		b0 += B;
		c0 += C;
		d0 += D;
	}
	ssl->size_hash = 4;
	ssl->hash[0] = little_endian ? switch_endian(a0) : a0;
	ssl->hash[1] = little_endian ? switch_endian(b0) : b0;
	ssl->hash[2] = little_endian ? switch_endian(c0) : c0;
	ssl->hash[3] = little_endian ? switch_endian(d0) : d0;
}
