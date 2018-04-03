/*
  Include glib.h and pbc.h before including this file. Note that this
  file should be included at most once.
*/

#if defined (__cplusplus)
extern "C" {
#endif

/*
  A public key.
*/
typedef struct bswabe_pub_s bswabe_pub_t;

/*
  A master secret key.
*/
typedef struct bswabe_msk_s bswabe_msk_t;

/*
  A private key.
*/
typedef struct bswabe_prv_s bswabe_prv_t;

/*
  A time token.
*/
typedef struct bswabe_token_s bswabe_token_t;

/*
  A ciphertext. Note that this library only handles encrypting a
  single group element, so if you want to encrypt something bigger,
  you will have to use that group element as a symmetric key for
  hybrid encryption (which you do yourself).
*/
typedef struct bswabe_cph_s bswabe_cph_t;

typedef struct bswabe_rekey_s bswabe_rekey_t;

typedef struct bswabe_rcp_s bswabe_rcp_t;

/*
  Generate a public key and corresponding master secret key, and
  assign the *pub and *msk pointers to them. The space used may be
  later freed by calling bswabe_pub_free(*pub) and
  bswabe_msk_free(*msk).
*/
void bswabe_setup( bswabe_pub_t** pub, bswabe_msk_t** msk );

/*
  Generate a private key with the given set of attributes. The final
  argument should be a null terminated array of pointers to strings,
  one for each attribute.
*/
bswabe_prv_t* bswabe_keygen( bswabe_pub_t* pub,
                             bswabe_msk_t* msk,
			     char* identity,
                             char** attributes );

bswabe_token_t* bswabe_tokengen( bswabe_pub_t* pub, bswabe_msk_t* msk, char* timek );

/*
  Pick a random group element and encrypt it under the specified
  access policy. The resulting ciphertext is returned and the
  element_t given as an argument (which need not be initialized) is
  set to the random group element.

  After using this function, it is normal to extract the random data
  in m using the pbc functions element_length_in_bytes and
  element_to_bytes and use it as a key for hybrid encryption.

  The policy is specified as a simple string which encodes a postorder
  traversal of threshold tree defining the access policy. As an
  example,

    "foo bar fim 2of3 baf 1of2"

  specifies a policy with two threshold gates and four leaves. It is
  not possible to specify an attribute with whitespace in it (although
  "_" is allowed).

  Numerical attributes and any other fancy stuff are not supported.

  Returns null if an error occured, in which case a description can be
  retrieved by calling bswabe_error().
*/
bswabe_cph_t* bswabe_enc( bswabe_pub_t* pub, element_t m, char* policy, char** identities );

/*
  Decrypt the specified ciphertext using the given private key,
  filling in the provided element m (which need not be initialized)
  with the result.

  Returns true if decryption succeeded, false if this key does not
  satisfy the policy of the ciphertext (in which case m is unaltered).
*/
bswabe_rekey_t* bswabe_rekeygen( bswabe_pub_t* pub, bswabe_prv_t* prv, char* identity, char** identities );

bswabe_rcp_t* bswabe_reenc( bswabe_pub_t* pub, bswabe_rekey_t* rekey, char* identity, bswabe_cph_t* cph, bswabe_token_t* token );

int bswabe_dec1( bswabe_pub_t* pub, bswabe_prv_t* prv, char* identity, bswabe_cph_t* cph, element_t m );

int bswabe_dec2( bswabe_pub_t* pub, bswabe_prv_t* prv, char* identity, bswabe_rcp_t* rcp, element_t m );

/*
  Exactly what it seems.
*/
GByteArray* bswabe_pub_serialize( bswabe_pub_t* pub );
GByteArray* bswabe_msk_serialize( bswabe_msk_t* msk );
GByteArray* bswabe_prv_serialize( bswabe_prv_t* prv );
GByteArray* bswabe_token_serialize( bswabe_token_t* token );
GByteArray* bswabe_cph_serialize( bswabe_cph_t* cph );
GByteArray* bswabe_rekey_serialize( bswabe_rekey_t* rekey );
GByteArray* bswabe_rcp_serialize( bswabe_rcp_t* cph );

/*
  Also exactly what it seems. If free is true, the GByteArray passed
  in will be free'd after it is read.
*/
bswabe_pub_t* bswabe_pub_unserialize( GByteArray* b, int free );
bswabe_msk_t* bswabe_msk_unserialize( bswabe_pub_t* pub, GByteArray* b, int free );
bswabe_prv_t* bswabe_prv_unserialize( bswabe_pub_t* pub, GByteArray* b, int free );
bswabe_token_t* bswabe_token_unserialize( bswabe_pub_t* pub, GByteArray* b, int free );
bswabe_cph_t* bswabe_cph_unserialize( bswabe_pub_t* pub, GByteArray* b, int free );
bswabe_rekey_t* bswabe_rekey_unserialize( bswabe_pub_t* pub, GByteArray* b, int free );
bswabe_rcp_t* bswabe_rcp_unserialize( bswabe_pub_t* pub, GByteArray* b, int free );

/*
  Again, exactly what it seems.
*/
void bswabe_pub_free( bswabe_pub_t* pub );
void bswabe_msk_free( bswabe_msk_t* msk );
void bswabe_prv_free( bswabe_prv_t* prv );
void bswabe_token_free( bswabe_token_t* token );
void bswabe_cph_free( bswabe_cph_t* cph );
void bswabe_rekey_free( bswabe_rekey_t* rekey );
void bswabe_rcp_free( bswabe_rcp_t* cph );

/*
  Return a description of the last error that occured. Call this after
  bswabe_enc or bswabe_dec returns 0. The returned string does not
  need to be free'd.
*/
char* bswabe_error();

#if defined (__cplusplus)
} // extern "C"
#endif
