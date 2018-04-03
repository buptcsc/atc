/*
	Include glib.h, pbc.h, and bswabe.h before including this file.
*/

#define N 30

struct bswabe_pub_s
{
	char* pairing_desc;
	pairing_t p;
	element_t h;             /* G_1 */
	element_t h_beta;        /* G_1 */
	element_t h_alpha;       /* G_1 */
	element_t h_power[N];    /* G_1 */
	element_t u;             /* G_2 */
	element_t u_beta;        /* G_2 */
	element_t u_power[N];    /* G_2 */
	element_t g_h_hat;       /* G_T */
	element_t g_h_hat_gamma; /* G_T */
	element_t g_gamma;       /* G_2 */
};

struct bswabe_msk_s
{
	element_t g;        /* G_2 */
	element_t gamma;    /* Z_r */
	element_t beta;     /* Z_r */
	element_t alpha;    /* Z_r */
};

typedef struct
{
	/* these actually get serialized */
	char* attr;
	element_t d;  /* G_2 */
	element_t dp; /* G_1 */

	/* only used during dec (only by dec_merge) */
	int used;
	element_t z;  /* G_1 */
	element_t zp; /* G_1 */
}
bswabe_prv_comp_t;

struct bswabe_prv_s
{
	element_t s;   /* G_2 */
	element_t d;   /* G_2 */
	GArray* comps; /* bswabe_prv_comp_t's */
};

typedef struct
{
	element_t tk;  /* G_2 */
}
bswabe_token_comp_t;

struct bswabe_token_s
{
	GArray* comps;
};

typedef struct
{
	int deg;
	/* coefficients from [0] x^0 to [deg] x^deg */
	element_t* coef; /* G_T (of length deg + 1) */
}
bswabe_polynomial_t;

typedef struct
{
	/* serialized */
	int k;            /* one if leaf, otherwise threshold */
	char* attr;       /* attribute string if leaf, otherwise null */
	element_t c;      /* G_1, only for leaves */
	element_t cp;     /* G_1, only for leaves */
	GPtrArray* children; /* pointers to bswabe_policy_t's, len == 0 for leaves */

	/* only used during encryption */
	bswabe_polynomial_t* q;

	/* only used during decryption */
	int satisfiable;
	int min_leaves;
	int attri;
	GArray* satl;
}
bswabe_policy_t;

typedef struct
{
	/* serialized */
	char* identity;       /* attribute string if leaf, otherwise null */
}
bswabe_identity_t;

typedef struct
{
	element_t a;  /* G_1 */
	element_t b;  /* Z_r */
}
bswabe_time_t;

struct bswabe_cph_s
{
	element_t c1; /* G_T */
	element_t c2; /* G_1 */
	element_t c3; /* G_2 */
	element_t c4; /* G_2 */
	element_t c5; /* G_1 */
	element_t c6; /* G_T */
	bswabe_policy_t* p;
	GArray* id;
	GArray* t;
};

struct bswabe_rekey_s
{
	element_t r1;  /* G_2 */
	element_t r2;  /* G_1 */
	element_t r3;  /* G_1 */
	element_t r4;  /* G_2 */
	element_t r5;  /* G_2 */
	GArray* comps; /* bswabe_prv_comp_t's */
	GArray* id;
};

struct bswabe_rcp_s
{
	element_t c1; /* G_T */
	element_t c2; /* G_1 */
	element_t c3; /* G_1 */
	element_t c4; /* G_2 */
	element_t c5; /* G_T */
	element_t c6; /* G_2 */
	GArray* id;
};
