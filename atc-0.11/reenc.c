#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "bswabe.h"
#include "common.h"

char* usage =
"Usage: mdmc-reenc [OPTION ...] PUB_KEY PRIV_KEY FILE\n"
"\n"
"Decrypt FILE using private key PRIV_KEY and assuming public key\n"
"PUB_KEY. If the name of FILE is X.cpabe, the decrypted file will\n"
"be written as X and FILE will be removed. Otherwise the file will be\n"
"decrypted in place. Use of the -o option overrides this\n"
"behavior.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -k, --keep-input-file    don't delete original file\n\n"
" -o, --output FILE        write output to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
/* " -s, --no-opt-sat         pick an arbitrary way of satisfying the policy\n" */
/* "                          (only for performance comparison)\n\n" */
/* " -n, --naive-dec          use slower decryption algorithm\n" */
/* "                          (only for performance comparison)\n\n" */
/* " -f, --flatten            use slightly different decryption algorithm\n" */
/* "                          (may result in higher or lower performance)\n\n" */
/* " -r, --report-ops         report numbers of group operations\n" */
/* "                          (only for performance evaluation)\n\n" */
"";

/* enum { */
/* 	DEC_NAIVE, */
/* 	DEC_FLATTEN, */
/* 	DEC_MERGE, */
/* } dec_strategy = DEC_MERGE;		 */

char* pub_file   = 0;
char* rekey_file = 0;
char* token_file = 0;
char* in_file    = 0;
char* out_file   = 0;
int   keep       = 0;
char* identity   = 0;
char* pattern    = 0;
int   coowner    = 0;

void
parse_args( int argc, char** argv )
{
	int i;

	for( i = 1; i < argc; i++ )
		if(      !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
		{
			printf("%s", usage);
			exit(0);
		}
		else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
		{
			printf(CPABE_VERSION, "-dec");
			exit(0);
		}
		else if( !strcmp(argv[i], "-k") || !strcmp(argv[i], "--keep-input-file") )
		{
			keep = 1;
		}
		else if( !strcmp(argv[i], "-o") || !strcmp(argv[i], "--output") )
		{
			if( ++i >= argc )
				die(usage);
			else
				out_file = argv[i];
		}
		else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
		{
			pbc_random_set_deterministic(0);
		}
		else if( !strcmp(argv[i], "-p") )
		{
			pattern = argv[++i];
			printf("pattern: %s\n", pattern);
		}
		else if( !pub_file )
		{
			pub_file = argv[i];
		}
		else if( !rekey_file )
		{
			rekey_file = argv[i];
		}
		else if( !token_file )
		{
			token_file = argv[i];
		}
		else if( !identity )
		{
			identity = argv[i];
		}
		else if( !in_file )
		{
			in_file = argv[i];
		}
		else
			die(usage);

	if( !pub_file || !rekey_file || !in_file )
		die(usage);

	if( !out_file )
	{
		if(  strlen(in_file) > 4 &&
				!strcmp(in_file + strlen(in_file) - 4, ".enc") )
			out_file = g_strdup_printf("%s.rec", in_file);
		else
			out_file = strdup(in_file);
	}
	
	if( keep && !strcmp(in_file, out_file) )
		die("cannot keep input file when decrypting file in place (try -o)\n");
}

int
main( int argc, char** argv )
{
	bswabe_pub_t* pub;
	bswabe_rekey_t* rekey;
	bswabe_cph_t* cph;
	bswabe_rcp_t* rcp;
	bswabe_token_t* token;
	struct timeval t1, t2;
	float cost;

	int file_len;
	GByteArray* aes_buf;
	GByteArray* cph_buf;
	GByteArray* rcp_buf;

	parse_args(argc, argv);

	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
	rekey = bswabe_rekey_unserialize(pub, suck_file(rekey_file), 1);

	read_cpabe_file(in_file, &cph_buf, &file_len, &aes_buf);
	cph = bswabe_cph_unserialize(pub, cph_buf, 1);

	token = bswabe_token_unserialize(pub, suck_file(token_file), 1);

	//////////////////////////////////////////////////////
	gettimeofday(&t1, NULL);
	printf("t1: %ld.%ld\n", t1.tv_sec, t1.tv_usec);
	//////////////////////////////////////////////////////
	
	if( !(rcp = bswabe_reenc(pub, rekey, identity, cph, token) ))
		die("%s", bswabe_error());
	bswabe_cph_free(cph);

	//////////////////////////////////////////////////////
	gettimeofday(&t2, NULL);
	printf("t2: %ld.%ld\n", t2.tv_sec, t2.tv_usec);

	cost = ((t2.tv_sec-t1.tv_sec)*1000000 + (t2.tv_usec-t1.tv_usec))/1000.0;
	printf("cost: %f\n", cost);
	/////////////////////////////////////////////////////

	rcp_buf = bswabe_rcp_serialize(rcp);
	bswabe_rcp_free(rcp);

	write_cpabe_file(out_file, rcp_buf, file_len, aes_buf);

	g_byte_array_free(aes_buf, 1);
	g_byte_array_free(rcp_buf, 1);

	/*if( !keep )
		unlink(in_file);*/

	return 0;
}
