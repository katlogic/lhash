#include "lhash.h"

/* initialize rng */
static	void	rand_collect(SHA1 *ctx, int count)
{
	char	garbage[128];
	struct	timeval tv;
	int	i;

	gettimeofday(&tv, NULL);
	/* skip zeros */
	for (i = 0; i < sizeof(garbage); i++) {
		if (garbage[i]) {
			sha1_update(ctx, garbage + i, sizeof(garbage) - i);
			break;
		}
	}
	if (count--)
		rand_collect(ctx, count);
	/* to _prevent_ tail recursion */
	sha1_update(ctx, &count, sizeof(count));
	sha1_update(ctx, &tv, sizeof(tv));
}

static	int rfd;
static	u8 digest[SHA1_DIGEST_SIZE];
static	int doff;

static	void	rand_init()
{
	rfd = open("/dev/urandom", O_RDONLY);
	if (rfd >= 0)
		return;
	doff = SHA1_DIGEST_SIZE;
}

void	rand_bytes(u8 *buf, int count)
{
	static int inited = 0;
	if (!inited) { rand_init(); inited = 1; }
	if (rfd >= 0) {
		read(rfd, buf, count);
		return;
	}
	/* otherwise use our little prng */
	while (count > 0) {
		int toc;
		/* we've to compute new digest */
		if (doff == SHA1_DIGEST_SIZE) {
			SHA1 ctx;
			sha1_init(&ctx);
			sha1_update(&ctx, digest, SHA1_DIGEST_SIZE);
			sha1_update(&ctx, buf, count);
			sha1_update(&ctx, &buf, sizeof(buf));
			sha1_update(&ctx, &count, sizeof(count));
			rand_collect(&ctx, 16);
			sha1_final(&ctx, digest);
			doff = 0;
		}
		toc = count<SHA1_DIGEST_SIZE-doff?count:SHA1_DIGEST_SIZE-doff;
		memcpy(buf, digest + doff, toc);
		buf += toc;
		count -= toc;
		doff += toc;
	}
}

