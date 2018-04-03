#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "bswabe.h"
#include "common.h"
#include "policy_lang.h"

char* usage =
"Usage: mdmc-enc [OPTION ...] PUB_KEY FILE [POLICY]\n"
"\n"
"Encrypt FILE under the decryption policy POLICY using public key\n"
"PUB_KEY. The encrypted file will be written to FILE.cpabe unless\n"
"the -o option is used. The original file will be removed. If POLICY\n"
"is not specified, the policy will be read from stdin.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -k, --keep-input-file    don't delete original file\n\n"
" -o, --output FILE        write resulting key to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

char* pub_file = 0;
char* in_file  = 0;
char* out_file = 0;
int   keep     = 0;
char** ids     = 0;

char* policy   = 0;

void
parse_args( int argc, char** argv )
{
	int i;
	GSList* alist;
	GSList* ap;
	int n;

	alist = 0;
	for( i = 1; i < argc; i++ )
		if(      !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
		{
			printf("%s", usage);
			exit(0);
		}
		else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
		{
			printf(CPABE_VERSION, "-enc");
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
		else if( !pub_file )
		{
			pub_file = argv[i];
		}
		else if( !in_file )
		{
			in_file = argv[i];
		}
		else if( !policy )
		{
			policy = parse_policy_lang(argv[i]);
		}
		else
		{
			alist = g_slist_append(alist, argv[i]);
		}

	if( !pub_file || !in_file )
		die(usage);

	if( !out_file )
		out_file = g_strdup_printf("%s.enc", in_file);

	n = g_slist_length(alist);
	ids = malloc((n + 1) * sizeof(char*));

	i = 0;
	for( ap = alist; ap; ap = ap->next )
	{
		ids[i++] = ap->data;
	}
	ids[i] = 0;
}

int
main( int argc, char** argv )
{
	bswabe_pub_t* pub;
	bswabe_cph_t* cph;
	int file_len;
	GByteArray* plt;
	GByteArray* cph_buf;
	GByteArray* aes_buf;
	element_t m;
	struct timeval t1, t2;
	float cost;

	parse_args(argc, argv);

	plt = suck_file(in_file);
	file_len = plt->len;

	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);

	//////////////////////////////////////////////////////
	gettimeofday(&t1, NULL);
	printf("t1: %ld.%ld\n", t1.tv_sec, t1.tv_usec);
	//////////////////////////////////////////////////////

  	if( !(cph = bswabe_enc(pub, m, policy, ids)) )
		die("%s", bswabe_error());		
	free(policy);
	
	aes_buf = aes_128_cbc_encrypt(plt, m);
	g_byte_array_free(plt, 1);
	element_clear(m);

	//////////////////////////////////////////////////////
	gettimeofday(&t2, NULL);
	printf("t2: %ld.%ld\n", t2.tv_sec, t2.tv_usec);

	cost = ((t2.tv_sec-t1.tv_sec)*1000000 + (t2.tv_usec-t1.tv_usec))/1000.0;
	printf("cost: %f\n", cost);
	/////////////////////////////////////////////////////

	cph_buf = bswabe_cph_serialize(cph);
	bswabe_cph_free(cph);	

	write_cpabe_file(out_file, cph_buf, file_len, aes_buf);

	g_byte_array_free(cph_buf, 1);
	g_byte_array_free(aes_buf, 1);

	/*if( !keep )
		unlink(in_file);*/

	return 0;
}
