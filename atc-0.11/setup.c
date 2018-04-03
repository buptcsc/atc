#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "bswabe.h"
#include "common.h"

char* usage =
"Usage: mdmc-setup [OPTION ...]\n"
"\n"
"Generate system parameters, a public key, and a master secret key\n"
"for use with cpabe-keygen, cpabe-enc, and cpabe-dec.\n"
"\n"
"Output will be written to the files \"pub_key\" and \"master_key\"\n"
"unless the --output-public-key or --output-master-key options are\n"
"used.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help                    print this message\n\n"
" -v, --version                 print version information\n\n"
" -p, --output-public-key FILE  write public key to FILE\n\n"
" -m, --output-master-key FILE  write master secret key to FILE\n\n"
" -d, --deterministic           use deterministic \"random\" numbers\n"
"                               (only for debugging)\n\n"
"";

char* pub_file = "pub_key";
char* msk_file = "master_key";

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
			printf(CPABE_VERSION, "-setup");
			exit(0);
		}
		else if( !strcmp(argv[i], "-p") || !strcmp(argv[i], "--output-public-key") )
		{
			if( ++i >= argc )
				die(usage);
			else
				pub_file = argv[i];
		}
		else if( !strcmp(argv[i], "-m") || !strcmp(argv[i], "--output-master-key") )
		{
			if( ++i >= argc )
				die(usage);
			else
				msk_file = argv[i];
		}
		else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
		{
			pbc_random_set_deterministic(0);
		}
		else
			die(usage);
}

int
main( int argc, char** argv )
{
	bswabe_pub_t* pub;
	bswabe_msk_t* msk;
	struct timeval t1, t2;
	float cost;

	parse_args(argc, argv);

	//////////////////////////////////////////////////////
	gettimeofday(&t1, NULL);
	printf("t1: %ld.%ld\n", t1.tv_sec, t1.tv_usec);
	//////////////////////////////////////////////////////

	bswabe_setup(&pub, &msk);

	//////////////////////////////////////////////////////
	gettimeofday(&t2, NULL);
	printf("t2: %ld.%ld\n", t2.tv_sec, t2.tv_usec);

	cost = ((t2.tv_sec-t1.tv_sec)*1000000 + (t2.tv_usec-t1.tv_usec))/1000.0;
	printf("cost: %f\n", cost);
	/////////////////////////////////////////////////////

	spit_file(pub_file, bswabe_pub_serialize(pub), 1);
	spit_file(msk_file, bswabe_msk_serialize(msk), 1);

	return 0;
}
