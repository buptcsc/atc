#include <stdlib.h>
#include <string.h>
#ifndef BSWABE_DEBUG
#define NDEBUG
#endif
#include <assert.h>

#include <openssl/sha.h>
#include <glib.h>
#include <pbc.h>

#include "bswabe.h"
#include "private.h"

#define TYPE_A_PARAMS \
"type a\n" \
"q 87807107996633125224377819847540498158068831994142082" \
"1102865339926647563088022295707862517942266222142315585" \
"8769582317459277713367317481324925129998224791\n" \
"h 12016012264891146079388821366740534204802954401251311" \
"822919615131047207289359704531102844802183906537786776\n" \
"r 730750818665451621361119245571504901405976559617\n" \
"exp2 159\n" \
"exp1 107\n" \
"sign1 1\n" \
"sign0 1\n"

char last_error[256];

char*
bswabe_error()
{
	return last_error;
}

void
raise_error(char* fmt, ...)
{
	va_list args;

#ifdef BSWABE_DEBUG
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	exit(1);
#else
	va_start(args, fmt);
	vsnprintf(last_error, 256, fmt, args);
	va_end(args);
#endif
}

void element_print( char* t, element_t e )
{
	uint32_t len;
	unsigned char* buf;

	len = element_length_in_bytes(e);
	buf = (unsigned char*) malloc(len+1);
	element_to_bytes(buf, e);
	buf[len] = '\0';

	printf("**--%s--%s---%d---\n", t, buf, len);

	free(buf);
}

void
element_from_string( element_t h, char* s )
{
	unsigned char* r;

	r = malloc(SHA_DIGEST_LENGTH);
	SHA1((unsigned char*) s, strlen(s), r);
	element_from_hash(h, r, SHA_DIGEST_LENGTH);

	free(r);
}

void
element_from_element( element_t h, element_t s )
{
	unsigned char* r;
	uint32_t len;
	unsigned char* buf;

	len = element_length_in_bytes(s);
	buf = (unsigned char*) malloc(len);
	element_to_bytes(buf, s);

	r = malloc(SHA_DIGEST_LENGTH);
	SHA1(buf, len, r);
	element_from_hash(h, r, SHA_DIGEST_LENGTH);

	free(buf);
	free(r);
}

void
compute_mul1( bswabe_pub_t* pub, char** identities, GArray* id, element_t r )
{
	element_t h_temp;
	element_t h_mul;
	element_t identity_hash[N];
	element_t identity_efficient[N];
	int i;
	int j;
	int len;

	element_init_Zr(h_temp, pub->p);
	element_init_G1(h_mul, pub->p);

	for( i = 0; i < N; i++ )
	{
		element_init_Zr(identity_hash[i], pub->p);
		element_init_Zr(identity_efficient[i], pub->p);

		element_set0(identity_efficient[i]);
	}

	/* compute */
	len = 0;
	while( *identities )
	{
		bswabe_identity_t idt;
		element_t h_id;

		element_init_Zr(h_id, pub->p);
		element_from_string(h_id, *identities);
			
		element_set(identity_hash[len], h_id);

		idt.identity = *(identities++);
		g_array_append_val(id, idt);
		element_clear(h_id);

		len++;
	}

	element_set1(identity_efficient[len]);
	for (j = 0; j < len; j++)
	{
		for (i = len - j - 1; i < len - 1; i++) {
			element_mul(h_temp, identity_efficient[i + 1], identity_hash[j]);
			element_add(identity_efficient[i], identity_efficient[i], h_temp);
		}
		element_add(identity_efficient[len-1], identity_efficient[len-1], identity_hash[j]);
	}

	element_set1(r);
	element_pow_zn(r, pub->h, identity_efficient[0]);
	for (j = 1; j <= len; j++)
	{
		element_pow_zn(h_mul, pub->h_power[j-1], identity_efficient[j]);
		element_mul(r, r, h_mul);
	}
}

void
compute_mul2( bswabe_pub_t* pub, char** identities, element_t r )
{
	element_t h_temp;
	element_t u_mul;
	element_t id_mul;
	element_t identity_hash[N];
	element_t identity_efficient[N];
	int i;
	int j;
	int len;

	element_init_Zr(h_temp, pub->p);
	element_init_Zr(id_mul, pub->p);
	element_init_G2(u_mul, pub->p);

	for( i = 0; i < N; i++ )
	{
		element_init_Zr(identity_hash[i], pub->p);
		element_init_Zr(identity_efficient[i], pub->p);

		element_set0(identity_efficient[i]);
	}

	/* compute */
	element_set1(id_mul);
	len = 0;
	while( *identities )
	{
		element_t h_id;

		element_init_Zr(h_id, pub->p);
		element_from_string(h_id, *(identities++));

		element_set(identity_hash[len], h_id);
		element_mul(id_mul, id_mul, h_id);

		element_clear(h_id);

		len++;
	}

	element_set1(identity_efficient[len]);
	for (j = 0; j < len; j++)
	{
		for (i = len - j - 1; i < len - 1; i++) {
			element_mul(h_temp, identity_efficient[i + 1], identity_hash[j]);
			element_add(identity_efficient[i], identity_efficient[i], h_temp);
		}
		element_add(identity_efficient[len-1], identity_efficient[len-1], identity_hash[j]);
	}

	element_set1(r);
	element_pow_zn(r, pub->u, identity_efficient[0]);
	for (j = 1; j <= len; j++)
	{
		element_pow_zn(u_mul, pub->u_power[j-1], identity_efficient[j]);
		element_mul(r, r, u_mul);
	}

	element_invert(id_mul, id_mul);
	element_pow_zn(r, r, id_mul);
}

void
compute_mul3( bswabe_pub_t* pub, element_t c4, GArray* id, char* identity, element_t sk, element_t c2, int flag, element_t r )
{
	element_t id_mul;
	element_t h_temp;
	element_t h_temp2;
	element_t h_result;	
	element_t t;
	element_t identity_hash[N];
	element_t identity_efficient[N];
	int i;
	int j;
	int len;
	
	element_init_Zr(id_mul, pub->p);
	element_init_Zr(h_temp, pub->p);
	element_init_G1(h_temp2, pub->p);
	element_init_G1(h_result, pub->p);
	element_init_GT(t, pub->p);

	for( i = 0; i < N; i++ )
	{
		element_init_Zr(identity_hash[i], pub->p);
		element_init_Zr(identity_efficient[i], pub->p);

		element_set0(identity_efficient[i]);
	}

	element_set1(id_mul);
	for( i = 0, len = 0; i < id->len; i++ )
	{
		bswabe_identity_t* idt;
		element_t h_id;

		element_init_Zr(h_id, pub->p);
		idt = &(g_array_index(id, bswabe_identity_t, i));		
		
		if( strcmp(idt->identity, identity) != 0 )
		{	
			element_from_string(h_id, idt->identity);
			element_set(identity_hash[len], h_id);
			element_mul(id_mul, id_mul, h_id);
			len++;
		}

		element_clear(h_id);
	}

	element_set1(identity_efficient[len]);
	for (j = 0; j < len; j++)
	{
		for (i = len - j - 1; i < len - 1; i++) {
			element_mul(h_temp, identity_efficient[i + 1], identity_hash[j]);
			element_add(identity_efficient[i], identity_efficient[i], h_temp);
		}
		element_add(identity_efficient[len-1], identity_efficient[len-1], identity_hash[j]);
	}

	element_set1(h_result);
	element_pow_zn(h_result, pub->h, identity_efficient[1]);
	for (j = 2; j <= len; j++)
	{
		element_pow_zn(h_temp2, pub->h_power[j-2], identity_efficient[j]);
		element_mul(h_result, h_result, h_temp2);
	}
	
	pairing_apply(r, c4, h_result, pub->p);
	pairing_apply(t, sk, c2, pub->p);	
	element_mul(r, r, t);
	
	element_invert(id_mul, id_mul);
	if (flag == 1) {
		element_neg(id_mul, id_mul);
	}
	element_pow_zn(r, r, id_mul);
}

void
bswabe_setup( bswabe_pub_t** pub, bswabe_msk_t** msk )
{
	int i;
	element_t index;
	element_t gamma_n;

	/* initialize */
	*pub = malloc(sizeof(bswabe_pub_t));
	*msk = malloc(sizeof(bswabe_msk_t));

	(*pub)->pairing_desc = strdup(TYPE_A_PARAMS);
	pairing_init_set_buf((*pub)->p, (*pub)->pairing_desc, strlen((*pub)->pairing_desc));

	element_init_G1((*pub)->h,           (*pub)->p);
	element_init_G1((*pub)->h_beta,      (*pub)->p);
	element_init_G1((*pub)->h_alpha,     (*pub)->p);
	element_init_G2((*pub)->u,           (*pub)->p);
	element_init_G2((*pub)->u_beta,      (*pub)->p);
	for( i = 0; i < N; i++ )
	{
		element_init_G1((*pub)->h_power[i],      (*pub)->p);
		element_init_G2((*pub)->u_power[i],      (*pub)->p);
	}
	
	element_init_GT((*pub)->g_h_hat,       (*pub)->p);
	element_init_GT((*pub)->g_h_hat_gamma, (*pub)->p);
	element_init_G2((*pub)->g_gamma,       (*pub)->p);
	
	element_init_G2((*msk)->g,           (*pub)->p);	
	element_init_Zr((*msk)->gamma,       (*pub)->p);
	element_init_Zr((*msk)->beta,        (*pub)->p);
	element_init_Zr((*msk)->alpha,       (*pub)->p);
	
	element_init_Zr(index,               (*pub)->p);
	element_init_Zr(gamma_n,             (*pub)->p);

	/* compute */
	element_random((*msk)->g);
	element_random((*msk)->gamma);
 	element_random((*msk)->beta);
	element_random((*msk)->alpha);
	element_random((*pub)->h);
	element_random((*pub)->u);

	element_pow_zn((*pub)->h_beta, (*pub)->h, (*msk)->beta);
	element_pow_zn((*pub)->h_alpha, (*pub)->h, (*msk)->alpha);
	element_pow_zn((*pub)->u_beta, (*pub)->u, (*msk)->beta);

	for( i = 0; i < N; i++ )
	{
		element_set_si(index, i + 1);
		element_pow_zn(gamma_n, (*msk)->gamma, index);
		element_pow_zn((*pub)->h_power[i], (*pub)->h, gamma_n);
		element_pow_zn((*pub)->u_power[i], (*pub)->u, gamma_n);
	}
	
	element_pow_zn((*pub)->g_gamma, (*msk)->g, (*msk)->gamma);	

	pairing_apply((*pub)->g_h_hat, (*pub)->h, (*msk)->g, (*pub)->p);
	pairing_apply((*pub)->g_h_hat_gamma, (*pub)->h, (*pub)->g_gamma, (*pub)->p);
}

bswabe_prv_t* bswabe_keygen( bswabe_pub_t* pub, bswabe_msk_t* msk, char* identity, char** attributes )
{
	bswabe_prv_t* prv;
	element_t g_r;
	element_t r;
	element_t h_id;/*--------*/
	element_t gamma_inv;/*--------*/
	element_t beta_inv;

	/* initialize */

	prv = malloc(sizeof(bswabe_prv_t));

	element_init_G2(prv->s, pub->p);/*--------*/
	element_init_G2(prv->d, pub->p);
	element_init_G2(g_r, pub->p);
	element_init_Zr(r, pub->p);
	element_init_Zr(h_id, pub->p);/*--------*/
	element_init_Zr(gamma_inv, pub->p);/*--------*/
	element_init_Zr(beta_inv, pub->p);

	prv->comps = g_array_new(0, 1, sizeof(bswabe_prv_comp_t));

	/* compute */

	element_from_string(h_id, identity);/*--------*/
	element_add(h_id, msk->gamma, h_id);
	element_invert(gamma_inv, h_id);/*--------*/
	element_pow_zn(prv->s, msk->g, gamma_inv);/*--------*/

 	element_random(r);
	element_pow_zn(g_r, msk->g, r);

	element_mul(prv->d, pub->g_gamma, g_r);
	element_invert(beta_inv, msk->beta);
	element_pow_zn(prv->d, prv->d, beta_inv);

	while( *attributes )
	{
		bswabe_prv_comp_t c;
		element_t h_rp;
		element_t rp;

		c.attr = *(attributes++);

		element_init_G2(c.d,  pub->p);
		element_init_G1(c.dp, pub->p);
		element_init_G2(h_rp, pub->p);
		element_init_Zr(rp,   pub->p);
		
 		element_from_string(h_rp, c.attr);
 		element_random(rp);

		element_pow_zn(h_rp, h_rp, rp);
		element_mul(c.d, g_r, h_rp);

		element_pow_zn(c.dp, pub->h, rp);

		element_clear(h_rp);
		element_clear(rp);

		g_array_append_val(prv->comps, c);
	}

	return prv;
}

bswabe_token_t* bswabe_tokengen( bswabe_pub_t* pub, bswabe_msk_t* msk, char* timek )
{
	bswabe_token_t* token;
	bswabe_token_comp_t c;
	element_t h_t;

	element_init_G2(h_t, pub->p);
	element_init_G2(c.tk,  pub->p);

	token = malloc(sizeof(bswabe_token_t));

	token->comps = g_array_new(0, 1, sizeof(bswabe_token_comp_t));
	
	element_from_string(h_t, timek);
	
	element_pow_zn(c.tk, h_t, msk->alpha);
	
	g_array_append_val(token->comps, c);

	return token;
}

bswabe_policy_t*
base_node( int k, char* s )
{
	bswabe_policy_t* p;

	p = (bswabe_policy_t*) malloc(sizeof(bswabe_policy_t));
	p->k = k;
	p->attr = s ? strdup(s) : 0;
	p->children = g_ptr_array_new();
	p->q = 0;

	return p;
}

/*
	TODO convert this to use a GScanner and handle quotes and / or
	escapes to allow attributes with whitespace or = signs in them
*/

bswabe_policy_t*
parse_policy_postfix( char* s )
{
	char** toks;
	char** cur_toks;
	char*  tok;
	GPtrArray* stack; /* pointers to bswabe_policy_t's */
	bswabe_policy_t* root;

	toks     = g_strsplit(s, " ", 0);
	cur_toks = toks;
	stack    = g_ptr_array_new();

	while( *cur_toks )
	{
		int i, k, n;

		tok = *(cur_toks++);

		if( !*tok )
			continue;

		if( sscanf(tok, "%dof%d", &k, &n) != 2 )
		{
			/* push leaf token */
			g_ptr_array_add(stack, base_node(1, tok));
		}
		else
		{
			bswabe_policy_t* node;

			/* parse "kofn" operator */

			if( k < 1 )
			{
				raise_error("error parsing \"%s\": trivially satisfied operator \"%s\"\n", s, tok);
				return 0;
			}
			else if( k > n )
			{
				raise_error("error parsing \"%s\": unsatisfiable operator \"%s\"\n", s, tok);
				return 0;
			}
			else if( n == 1 )
			{
				raise_error("error parsing \"%s\": identity operator \"%s\"\n", s, tok);
				return 0;
			}
			else if( n > stack->len )
			{
				raise_error("error parsing \"%s\": stack underflow at \"%s\"\n", s, tok);
				return 0;
			}
			
			/* pop n things and fill in children */
			node = base_node(k, 0);
			g_ptr_array_set_size(node->children, n);
			for( i = n - 1; i >= 0; i-- )
				node->children->pdata[i] = g_ptr_array_remove_index(stack, stack->len - 1);
			
			/* push result */
			g_ptr_array_add(stack, node);
		}
	}

	if( stack->len > 1 )
	{
		raise_error("error parsing \"%s\": extra tokens left on stack\n", s);
		return 0;
	}
	else if( stack->len < 1 )
	{
		raise_error("error parsing \"%s\": empty policy\n", s);
		return 0;
	}

	root = g_ptr_array_index(stack, 0);

 	g_strfreev(toks);
 	g_ptr_array_free(stack, 0);

	return root;
}

bswabe_polynomial_t*
rand_poly( int deg, element_t zero_val )
{
	int i;
	bswabe_polynomial_t* q;

	q = (bswabe_polynomial_t*) malloc(sizeof(bswabe_polynomial_t));
	q->deg = deg;
	q->coef = (element_t*) malloc(sizeof(element_t) * (deg + 1));

	for( i = 0; i < q->deg + 1; i++ )
	{
		element_init_same_as(q->coef[i], zero_val);
	}

	element_set(q->coef[0], zero_val);

	for( i = 1; i < q->deg + 1; i++ )
	{
 		element_random(q->coef[i]);
	}

	return q;
}

void
eval_poly( element_t r, bswabe_polynomial_t* q, element_t x )
{
	int i;
	element_t s, t;

	element_init_same_as(s, r);
	element_init_same_as(t, r);

	element_set0(r);
	element_set1(t);

	for( i = 0; i < q->deg + 1; i++ )
	{
		/* r += q->coef[i] * t */
		element_mul(s, q->coef[i], t);
		element_add(r, r, s);
		/* t *= x */
		element_mul(t, t, x);
	}

	element_clear(s);
	element_clear(t);
}

void
fill_policy( bswabe_cph_t* cph, bswabe_policy_t* p, bswabe_pub_t* pub, element_t e )
{
	int i;
	bswabe_policy_t* pi;
	element_t r;
	element_t t;
	element_t h;

	element_init_Zr(r, pub->p);
	element_init_Zr(t, pub->p);
	element_init_G2(h, pub->p);

	p->q = rand_poly(p->k - 1, e);

	if( p->children->len == 0 )
	{
		element_init_G1(p->c,  pub->p);
		element_init_G2(p->cp, pub->p);
		
		element_from_string(h, p->attr);

		/*if (strcmp(p->attr, "director") == 0)
		{
			element_t st;
			element_t rt;
			element_t h_t;
			element_t th;
			element_t h_th;
			bswabe_time_t tt;

			element_init_Zr(st, pub->p);
			element_init_Zr(rt, pub->p);
			element_init_G2(h_t, pub->p);
			element_init_GT(th, pub->p);
			element_init_Zr(h_th, pub->p);
			element_init_G1(tt.a, pub->p);
			element_init_Zr(tt.b, pub->p);
			
			element_random(st);
			element_random(rt);
			element_pow_zn(tt.a, pub->h, rt);

			element_from_string(h_t, "2018-01-18");

			pairing_apply(th, pub->h_alpha, h_t, pub->p);
			element_pow_zn(th, th, rt);
			element_from_element(h_th, th);
			
			element_add(tt.b, st, h_th);

			g_array_append_val(cph->t, tt);

			element_div(p->q->coef[0], p->q->coef[0], st);
		}*/

		element_pow_zn(p->c,  pub->h, p->q->coef[0]);
		element_pow_zn(p->cp, h,      p->q->coef[0]);
	}
	else
		for( i = 0; i < p->children->len; i++ )
		{
			element_set_si(r, i + 1);
			eval_poly(t, p->q, r);

			pi = g_ptr_array_index(p->children, i);

			if (pi->k == 1 && pi->children->len == 2)
			{
				element_t st;
				element_t rt;
				element_t h_t;
				element_t th;
				element_t h_th;
				bswabe_time_t tt;

				element_init_Zr(st, pub->p);
				element_init_Zr(rt, pub->p);
				element_init_G2(h_t, pub->p);
				element_init_GT(th, pub->p);
				element_init_Zr(h_th, pub->p);
				element_init_G1(tt.a, pub->p);
				element_init_Zr(tt.b, pub->p);
			
				element_random(st);
				element_random(rt);
				element_pow_zn(tt.a, pub->h, rt);

				element_from_string(h_t, "2018-01-18");

				pairing_apply(th, pub->h_alpha, h_t, pub->p);
				element_pow_zn(th, th, rt);
				element_from_element(h_th, th);
			
				element_add(tt.b, st, h_th);

				g_array_append_val(cph->t, tt);

				element_div(t, t, st);
			}

			fill_policy(cph, pi, pub, t);
		}

	element_clear(r);
	element_clear(t);
	element_clear(h);
}

void
result( bswabe_policy_t* p, bswabe_pub_t* pub )
{
	int i;
	bswabe_policy_t* pi;

	printf("%d %d \n", p->q->deg, p->children->len);	
	if(p->attr != NULL) printf("attr: %s\n", p->attr);

	for( i = 0; i < p->q->deg + 1; i++ )
	{
		printf("%d ", i);
		element_print("coef:", p->q->coef[i]);
	}
	
	for( i = 0; i < p->children->len; i++ )
	{
		pi = g_ptr_array_index(p->children, i);

		result(pi, pub);
	}
}

bswabe_policy_t*
merge_policy(bswabe_policy_t* cp, bswabe_policy_t* op)
{
	GPtrArray* stack;
	bswabe_policy_t* root;

	stack = g_ptr_array_new();

	g_ptr_array_add(stack, cp);
	g_ptr_array_add(stack, op);

	bswabe_policy_t* node = base_node(2, 0);
	g_ptr_array_set_size(node->children, 2);

	node->children->pdata[1] = g_ptr_array_remove_index(stack, stack->len - 1);
	node->children->pdata[0] = g_ptr_array_remove_index(stack, stack->len - 1);

	g_ptr_array_add(stack, node);

	root = g_ptr_array_index(stack, 0);

	g_ptr_array_free(stack, 0);

	return root;
}

bswabe_cph_t*
bswabe_enc( bswabe_pub_t* pub, element_t m, char* policy, char** identities )
{
	bswabe_cph_t* cph;
 	element_t s;
	element_t k;
	element_t kn;
	element_t u_mul;

	/* initialize */
	cph = malloc(sizeof(bswabe_cph_t));

	element_init_Zr(s, pub->p);
	element_init_Zr(k, pub->p);
	element_init_Zr(kn, pub->p);
	element_init_G2(u_mul, pub->p);
	element_init_GT(m, pub->p);
	element_init_GT(cph->c1, pub->p);
	element_init_G1(cph->c2, pub->p);
	element_init_G2(cph->c3, pub->p);
	element_init_G2(cph->c4, pub->p);
	element_init_G1(cph->c5, pub->p);
	element_init_GT(cph->c6, pub->p);

	cph->p = parse_policy_postfix(policy);
	cph->id = g_array_new(0, 1, sizeof(bswabe_identity_t));
	cph->t = g_array_new(0, 1, sizeof(bswabe_time_t));

	/* compute */
	compute_mul1(pub, identities, cph->id, cph->c2);
	compute_mul2(pub, identities, cph->c3);

 	element_random(m);	
	element_random(s);
	element_random(k);

	element_pow_zn(cph->c1, pub->g_h_hat, k);
	element_mul(cph->c1, cph->c1, m);

	element_pow_zn(cph->c2, cph->c2, k);
	element_pow_zn(cph->c3, cph->c3, k);
	element_pow_zn(u_mul, pub->u_beta, s);
	element_mul(cph->c3, cph->c3, u_mul);
	
	element_neg(kn, k);
	element_pow_zn(cph->c4, pub->g_gamma, kn);
	element_pow_zn(cph->c5, pub->h_beta, s);
	element_pow_zn(cph->c6, pub->g_h_hat_gamma, s);

	fill_policy(cph, cph->p, pub, s);

	return cph;
}

bswabe_rekey_t* bswabe_rekeygen( bswabe_pub_t* pub, bswabe_prv_t* prv, char* identity, char** identities )
{
	bswabe_rekey_t* rekey;
	element_t s2;
	element_t k2;
	element_t k2n;
	element_t h_id;
	element_t id_inv;
	element_t pair;
	element_t h_pair;
	int i;

	/* initialize */

	rekey = malloc(sizeof(bswabe_rekey_t));

	element_init_G2(rekey->r1, pub->p);
	element_init_G1(rekey->r2, pub->p);
	element_init_G1(rekey->r3, pub->p);
	element_init_G2(rekey->r4, pub->p);
	element_init_G2(rekey->r5, pub->p);
	element_init_Zr(s2, pub->p);
	element_init_Zr(k2, pub->p);
	element_init_Zr(k2n, pub->p);
	element_init_Zr(h_id, pub->p);
	element_init_Zr(id_inv, pub->p);
	element_init_GT(pair, pub->p);
	element_init_G1(h_pair, pub->p);

	rekey->id = g_array_new(0, 1, sizeof(bswabe_identity_t));

	/* compute */

 	element_random(s2);
	element_random(k2);

	element_from_string(h_id, identity);
	element_invert(id_inv, h_id);
	element_pow_zn(rekey->r1, pub->u, id_inv);
	element_pow_zn(rekey->r1, rekey->r1, s2);
	element_mul(rekey->r1, prv->s, rekey->r1);

	compute_mul1(pub, identities, rekey->id, rekey->r2);

	element_pow_zn(rekey->r2, rekey->r2, k2);

	element_pow_zn(pair, pub->g_h_hat, k2);
	element_from_element(h_pair, pair);
	element_pow_zn(rekey->r3, pub->h, s2);
	element_mul(rekey->r3, h_pair, rekey->r3);

	element_neg(k2n, k2);
	element_pow_zn(rekey->r4, pub->g_gamma, k2n);

	element_pow_zn(rekey->r5, pub->u, s2);
	element_mul(rekey->r5, prv->d, rekey->r5);

	rekey->comps = g_array_new(0, 1, sizeof(bswabe_prv_comp_t));

	for( i = 0; i < prv->comps->len; i++ )
	{
		bswabe_prv_comp_t c = g_array_index(prv->comps, bswabe_prv_comp_t, i);

		g_array_append_val(rekey->comps, c);
	}

	return rekey;
}

void
check_sat( bswabe_policy_t* p, bswabe_rekey_t* rekey )
{
	int i, l;

	p->satisfiable = 0;
	if( p->children->len == 0 )
	{
		for( i = 0; i < rekey->comps->len; i++ )
			if( !strcmp(g_array_index(rekey->comps, bswabe_prv_comp_t, i).attr,
									p->attr) )
			{
				p->satisfiable = 1;
				p->attri = i;
				break;
			}
	}
	else
	{
		for( i = 0; i < p->children->len; i++ )
			check_sat(g_ptr_array_index(p->children, i), rekey);

		l = 0;
		for( i = 0; i < p->children->len; i++ )
			if( ((bswabe_policy_t*) g_ptr_array_index(p->children, i))->satisfiable )
				l++;

		if( l >= p->k )
			p->satisfiable = 1;
	}
}

/* TODO there should be a better way of doing this */
bswabe_policy_t* cur_comp_pol;
int
cmp_int( const void* a, const void* b )
{
	int k, l;
	
	k = ((bswabe_policy_t*) g_ptr_array_index(cur_comp_pol->children, *((int*)a)))->min_leaves;
	l = ((bswabe_policy_t*) g_ptr_array_index(cur_comp_pol->children, *((int*)b)))->min_leaves;

	return
		k <  l ? -1 :
		k == l ?  0 : 1;
}

void
pick_sat_min_leaves( bswabe_policy_t* p, bswabe_rekey_t* rekey )
{
	int i, k, l;
	int* c;

	assert(p->satisfiable == 1);

	if( p->children->len == 0 )
		p->min_leaves = 1;
	else
	{
		for( i = 0; i < p->children->len; i++ )
			if( ((bswabe_policy_t*) g_ptr_array_index(p->children, i))->satisfiable )
				pick_sat_min_leaves(g_ptr_array_index(p->children, i), rekey);

		c = alloca(sizeof(int) * p->children->len);
		for( i = 0; i < p->children->len; i++ )
			c[i] = i;

		cur_comp_pol = p;
		qsort(c, p->children->len, sizeof(int), cmp_int);

		p->satl = g_array_new(0, 0, sizeof(int));
		p->min_leaves = 0;
		l = 0;

		for( i = 0; i < p->children->len && l < p->k; i++ )
			if( ((bswabe_policy_t*) g_ptr_array_index(p->children, c[i]))->satisfiable )
			{
				l++;
				p->min_leaves += ((bswabe_policy_t*) g_ptr_array_index(p->children, c[i]))->min_leaves;
				k = c[i] + 1;
				g_array_append_val(p->satl, k);
			}
		assert(l == p->k);
	}
}

void
lagrange_coef( element_t r, GArray* s, int i )
{
	int j, k;
	element_t t;

	element_init_same_as(t, r);

	element_set1(r);
	for( k = 0; k < s->len; k++ )
	{
		j = g_array_index(s, int, k);
		if( j == i )
			continue;
		element_set_si(t, - j);
		element_mul(r, r, t); /* num_muls++; */
		element_set_si(t, i - j);
		element_invert(t, t);
		element_mul(r, r, t); /* num_muls++; */
	}

	element_clear(t);
}

void
dec_leaf_flatten( element_t r, element_t exp, bswabe_policy_t* p, bswabe_rekey_t* rekey, bswabe_pub_t* pub, bswabe_cph_t* cph, bswabe_token_t* token )
{
	bswabe_prv_comp_t* c;
	element_t s;
	element_t t;

	c = &(g_array_index(rekey->comps, bswabe_prv_comp_t, p->attri));

	element_init_GT(s, pub->p);
	element_init_GT(t, pub->p);

	pairing_apply(s, p->c,  c->d,  pub->p); /* num_pairings++; */
	pairing_apply(t, p->cp, c->dp, pub->p); /* num_pairings++; */
	element_invert(t, t);
	element_mul(s, s, t); /* num_muls++; */

	//if (strcmp(p->attr, "director") == 0)
	if (strcmp(p->attr, "senior") == 0 || strcmp(p->attr, "manager") == 0)
	{
		element_t st;
		element_t th;
		element_t h_th;

		element_init_Zr(st, pub->p);
		element_init_GT(th, pub->p);
		element_init_Zr(h_th, pub->p);

		bswabe_token_comp_t* tc = &(g_array_index(token->comps, bswabe_token_comp_t, 0));
		bswabe_time_t* tt = &(g_array_index(cph->t, bswabe_time_t, 0));

		pairing_apply(th, tc->tk, tt->a, pub->p);
		element_from_element(h_th, th);
		
		element_sub(st, tt->b, h_th);

		element_pow_zn(s, s, st);
	}

	element_pow_zn(s, s, exp); /* num_exps++; */

	element_mul(r, r, s); /* num_muls++; */

	element_clear(s);
	element_clear(t);
}

void dec_node_flatten( element_t r, element_t exp, bswabe_policy_t* p, bswabe_rekey_t* rekey, bswabe_pub_t* pub, bswabe_cph_t* cph, bswabe_token_t* token );

void
dec_internal_flatten( element_t r, element_t exp, bswabe_policy_t* p, bswabe_rekey_t* rekey, bswabe_pub_t* pub, bswabe_cph_t* cph, bswabe_token_t* token )
{
	int i;
	element_t t;
	element_t expnew;

	element_init_Zr(t, pub->p);
	element_init_Zr(expnew, pub->p);

	for( i = 0; i < p->satl->len; i++ )
	{
 		lagrange_coef(t, p->satl, g_array_index(p->satl, int, i));
		element_mul(expnew, exp, t); /* num_muls++; */
		dec_node_flatten(r, expnew, g_ptr_array_index(p->children, g_array_index(p->satl, int, i) - 1), rekey, pub, cph, token);
	}

	element_clear(t);
	element_clear(expnew);
}

void
dec_node_flatten( element_t r, element_t exp, bswabe_policy_t* p, bswabe_rekey_t* rekey, bswabe_pub_t* pub, bswabe_cph_t* cph, bswabe_token_t* token )
{
	assert(p->satisfiable);
	if( p->children->len == 0 )
	{
		dec_leaf_flatten(r, exp, p, rekey, pub, cph, token);
	}
	else
	{
		dec_internal_flatten(r, exp, p, rekey, pub, cph, token);
	}
}

void
dec_flatten( element_t r, bswabe_policy_t* p, bswabe_rekey_t* rekey, bswabe_pub_t* pub, bswabe_cph_t* cph, bswabe_token_t* token )
{
	element_t one;

	element_init_Zr(one, pub->p);

	element_set1(one);
	element_set1(r);

	dec_node_flatten(r, one, p, rekey, pub, cph, token);

	element_clear(one);
}

bswabe_rcp_t*
bswabe_reenc( bswabe_pub_t* pub, bswabe_rekey_t* rekey, char* identity, bswabe_cph_t* cph, bswabe_token_t* token )
{
	bswabe_rcp_t* rcp;
	element_t a;
	element_t m;
	int i;

	rcp = malloc(sizeof(bswabe_rcp_t));

	element_init_GT(a, pub->p);
	element_init_GT(m, pub->p);	
	element_init_GT(rcp->c1, pub->p);
	element_init_G1(rcp->c2, pub->p);
	element_init_G1(rcp->c3, pub->p);
	element_init_G2(rcp->c4, pub->p);
	element_init_GT(rcp->c5, pub->p);
	element_init_G2(rcp->c6, pub->p);

	compute_mul3(pub, cph->c4, cph->id, identity, rekey->r1, cph->c2, 1, rcp->c1);
	element_mul(rcp->c1, rcp->c1, cph->c1);

	check_sat(cph->p, rekey);
	if( !cph->p->satisfiable )
	{
		raise_error("cannot re-encrypt, attributes in key do not satisfy policy\n");
		return 0;
	}

/* 	if( no_opt_sat ) */
/* 		pick_sat_naive(cph->p, prv); */
/* 	else */
	pick_sat_min_leaves(cph->p, rekey);

/* 	if( dec_strategy == DEC_NAIVE ) */
/* 		dec_naive(t, cph->p, prv, pub); */
/* 	else if( dec_strategy == DEC_FLATTEN ) */
	dec_flatten(a, cph->p, rekey, pub, cph, token);
/* 	else */
/* 		dec_merge(t, cph->p, prv, pub); */
	
	element_mul(m, cph->c6, a);
	element_invert(m, m);
	pairing_apply(rcp->c5, cph->c5, rekey->r5, pub->p);	
	element_mul(rcp->c5, rcp->c5, m);

	element_set(rcp->c2, rekey->r2);
	element_set(rcp->c3, rekey->r3);
	element_set(rcp->c4, rekey->r4);
	element_set(rcp->c6, cph->c3);

	rcp->id = g_array_new(0, 1, sizeof(bswabe_identity_t));

	for( i = 0; i < rekey->id->len; i++ )
	{
		bswabe_identity_t c = g_array_index(rekey->id, bswabe_identity_t, i);

		g_array_append_val(rcp->id, c);
	}

	return rcp;
}

int
bswabe_dec1( bswabe_pub_t* pub, bswabe_prv_t* prv, char* identity, bswabe_cph_t* cph, element_t m )
{
	element_t t;

	element_init_GT(m, pub->p);
	element_init_GT(t, pub->p);
	
	compute_mul3(pub, cph->c4, cph->id, identity, prv->s, cph->c2, 0, t);
	element_invert(t, t);
	element_mul(m, cph->c1, t);

	return 1;
}

int
bswabe_dec2( bswabe_pub_t* pub, bswabe_prv_t* prv, char* identity, bswabe_rcp_t* rcp, element_t m )
{
	element_t t;
	element_t h_pair;
	element_t z;
	element_t y;

	element_init_GT(m, pub->p);
	element_init_GT(t, pub->p);
	element_init_G1(h_pair, pub->p);
	element_init_G1(z, pub->p);
	element_init_GT(y, pub->p);

	compute_mul3(pub, rcp->c4, rcp->id, identity, prv->s, rcp->c2, 0, t);
	element_from_element(h_pair, t);
	element_invert(h_pair, h_pair);
	element_mul(z, rcp->c3, h_pair);

	pairing_apply(y, z, rcp->c6, pub->p);
	
	element_invert(rcp->c5, rcp->c5);
	element_mul(y, y, rcp->c5);
	element_mul(m, rcp->c1, y);

	return 1;
}
