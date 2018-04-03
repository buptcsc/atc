#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "bswabe.h"
#include "common.h"
#include "policy_lang.h"

char* usage =
"Usage: mdmc-rekeygen [OPTION ...] PUB_KEY MASTER_KEY ATTR [ATTR ...]\n"
"\n"
"Generate a key with the listed attributes using public key PUB_KEY and\n"
"master secret key MASTER_KEY. Output will be written to the file\n"
"\"priv_key\" unless the -o option is specified.\n"
"\n"
"Attributes come in two forms: non-numerical and numerical. Non-numerical\n"
"attributes are simply any string of letters, digits, and underscores\n"
"beginning with a letter.\n"
"\n"
"Numerical attributes are specified as `attr = N', where N is a non-negative\n"
"integer less than 2^64 and `attr' is another string. The whitespace around\n"
"the `=' is optional. One may specify an explicit length of k bits for the\n"
"integer by giving `attr = N#k'. Note that any comparisons in a policy given\n"
"to cpabe-enc(1) must then specify the same number of bits, e.g.,\n"
"`attr > 5#12'.\n"
"\n"
"The keywords `and', `or', and `of', are reserved for the policy language\n"
"of cpabe-enc (1) and may not be used for either type of attribute.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -o, --output FILE        write resulting key to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

/*
	TODO ensure we don't give out the same attribute more than once (esp
	as different numerical values)
*/

char* pub_file   = 0;
char* prv_file   = 0;
char* out_file   = 0;
int   keep       = 0;
char*  identity  = 0;
char** ids       = 0;

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
		else if( !pub_file )
		{
			pub_file = argv[i];
		}
		else if( !prv_file )
		{
			prv_file = argv[i];
		}
		else if( !identity )
		{
			identity = argv[i];
		}
		else
		{
			alist = g_slist_append(alist, argv[i]);
		}


	if( !pub_file || !prv_file )
		die(usage);
	
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
	bswabe_prv_t* prv;
	bswabe_rekey_t* rekey;
	struct timeval t1, t2;
	float cost;

	parse_args(argc, argv);

	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
	prv = bswabe_prv_unserialize(pub, suck_file(prv_file), 1);

	//////////////////////////////////////////////////////
	gettimeofday(&t1, NULL);
	printf("t1: %ld.%ld\n", t1.tv_sec, t1.tv_usec);
	//////////////////////////////////////////////////////
	
	rekey = bswabe_rekeygen(pub, prv, identity, ids);

	//////////////////////////////////////////////////////
	gettimeofday(&t2, NULL);
	printf("t2: %ld.%ld\n", t2.tv_sec, t2.tv_usec);

	cost = ((t2.tv_sec-t1.tv_sec)*1000000 + (t2.tv_usec-t1.tv_usec))/1000.0;
	printf("cost: %f\n", cost);
	/////////////////////////////////////////////////////

	spit_file(out_file, bswabe_rekey_serialize(rekey), 1);

	return 0;
}
