#include "../ssl_md5.h"

void			sha256_funct(char *message, t_ssl *ssl)
{
	int		k[64] = {
		0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
		0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
		0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
		0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
		0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
		0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
		0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
		0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
				};
	int		w[64];
	int		a0 = 0x6a09e667;
	int		b0 = 0xbb67ae85;
	int		c0 = 0x3c6ef372;
	int		d0 = 0xa54ff53a;
	int		e0 = 0x510e527f;
	int		f0 = 0x9b05688c;
	int		g0 = 0x1f83d9ab;
	int		h0 = 0x5be0cd19;
	int		T1, T2;
	char	*msg;
	int		nb_grps;
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
		unsigned int E = e0;
		unsigned int F = f0;
		unsigned int G = g0;
		unsigned int H = h0;
		/*i = -1;
		while (++i < 64)
			w[i] = i < 16 ? M[i] :
				O1(w[i - 2]) + w[i - 7] + O0(w[i - 15]) + w[i - 16];*/
		i = -1;
		while (++i < 64)
		{
			w[i] = i < 16 ? M[i] :
			O1(w[i - 2]) + w[i - 7] + O0(w[i - 15]) + w[i - 16];
			T1 = H + E1(E) + CH(E, F, G) + k[i] + w[i];
			T2 = E0(A) + MAJ(A, B, C);
			H = G;
			G = F;
			F = E;
			E = D + T1;
			D = C;
			C = B;
			B = A;
			A = T1 + T2;
		}
		a0 += A;
		b0 += B;
		c0 += C;
		d0 += D;
		e0 += E;
		f0 += F;
		g0 += G;
		h0 += H;
	}
	ssl->size_hash = 8;
	ssl->hash[0] = little_endian ? switch_endian(a0) : a0;
	ssl->hash[1] = little_endian ? switch_endian(b0) : b0;
	ssl->hash[2] = little_endian ? switch_endian(c0) : c0;
	ssl->hash[3] = little_endian ? switch_endian(d0) : d0;
	ssl->hash[4] = little_endian ? switch_endian(e0) : e0;
	ssl->hash[5] = little_endian ? switch_endian(f0) : f0;
	ssl->hash[6] = little_endian ? switch_endian(g0) : g0;
	ssl->hash[7] = little_endian ? switch_endian(h0) : h0;
}
