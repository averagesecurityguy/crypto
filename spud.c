/*
* A simple program to encrypt and decrypt files with a passphrase using
* libsodium, which is available here, http://doc.libsodium.org/index.html.
* 
* Note: The passphrase must be at least 20 characters long and is silently
*       truncated at 128 characters. These values can be adjusted using the
*       PHRASEMIN and PHRASEMAX constants.
*/
#include <string.h>
#include <sodium.h>

#define MACBYTES crypto_secretbox_MACBYTES
#define NONCEBYTES crypto_secretbox_NONCEBYTES
#define KEYBYTES crypto_secretbox_KEYBYTES
#define HASHBYTES crypto_generichash_BYTES
#define PHRASEMIN 20
#define PHRASEMAX 128
#define BUFBYTES 4096

typedef enum result {SUCCESS=0, FAIL=-1} result;

/*
* Function: open_file
* -------------------
* Attempt to open a file. If there is an error write it to stderr and return
* NULL.
*/
FILE *open_file(char* fname, char *mode)
{
    FILE *fp = fopen(fname, mode);

    if (fp == NULL)
    {
        fprintf(stderr, "Could not open file %s.\n", fname);
    }

    return fp;
}


/*
* Function: generate_key_nonce
* ----------------------------
* Attempt to generate a key and nonce using the passphrase and the static salt
* values. If there are any errors then return -1 otherwise return 0.
*/
result generate_key_nonce(unsigned char *key, unsigned char *nonce,
                          char *passphrase)
{
    char *key_salt = "wJDNGf7/Jrce41GTllX+Z4I0eHdva+IXFsYiD5Sg50M";
    char *nonce_salt = "6K9qNULNb0M61brPbbDFrA7zp8DULGb5G5tVRRpRFqk";
    size_t r;

    r = crypto_pwhash_scryptsalsa208sha256(
        key,
        KEYBYTES,
        passphrase,
        strlen(passphrase),
        (unsigned char *)key_salt,
        crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);

    if (r != 0)
    {
        fprintf(stderr, "Unable to generate key from passprase.\n");
        return FAIL;
    }

    r = crypto_pwhash_scryptsalsa208sha256(
        nonce,
        NONCEBYTES,
        passphrase,
        strlen(passphrase),
        (unsigned char *)nonce_salt,
        crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);

    if (r != 0)
    {
        fprintf(stderr, "Unable to generate nonce from passprase.\n");
        return FAIL;
    }

    return SUCCESS;
}


/*
* Function: encrypt_file
* ----------------------
* Encrypt a file by reading in chunks of data, encrypting those chunks, and
* writing the encrypted chunks to a new file.
*/
result encrypt_file(char *pfname, char *efname, unsigned char *k,
                    unsigned char *n)
{
    size_t rsize;
    size_t wsize;
    size_t r;
    unsigned char ebuf[BUFBYTES + MACBYTES];
    unsigned char pbuf[BUFBYTES];
    FILE *pfile;
    FILE *efile;

    pfile = open_file(pfname, "rb");
    if (pfile == NULL) { return FAIL; }

    efile = open_file(efname, "wb");
    if (efile == NULL) { fclose(pfile); return FAIL; }

    // Encrypt the data in the file in chunks.
    while (feof(pfile) == 0) {
        rsize = fread(pbuf, sizeof(unsigned char), BUFBYTES, pfile);

        r = crypto_secretbox_easy(ebuf, pbuf, rsize, n, k);
        if (r != 0)
        {
            fprintf(stderr, "Could not encrypt data.\n");
            fclose(pfile);
            fclose(efile);
            return FAIL;
        }

        // Write the encrypted bytes to a file. The encrypted bytes include
        // the MAC bytes as well.
        wsize = fwrite(ebuf, sizeof(unsigned char), rsize + MACBYTES, efile);
        if (wsize <= 0)
        {
            fprintf(stderr, "Could not write encrypted data to file.\n");
            fclose(pfile);
            fclose(efile);
            return FAIL;
        }
    }

    fclose(pfile);
    fclose(efile);

    return SUCCESS;
}


/*
* Function: decrypt_file
* ----------------------
* Decrypt a file by reading in chunks of data, decrypting those chunks, and
* writing the decrypted chunks to a new file.
*/
result decrypt_file(char *efname, char *pfname, unsigned char *k,
                   unsigned char *n)
{
    size_t rsize;
    size_t wsize;
    size_t r;
    unsigned char ebuf[BUFBYTES + MACBYTES];
    unsigned char pbuf[BUFBYTES];
    FILE *pfile;
    FILE *efile;

    pfile = open_file(pfname, "wb");
    if (pfile == NULL) { return FAIL; }

    efile = open_file(efname, "rb");
    if (efile == NULL) { fclose(pfile); return FAIL; }

    while (feof(efile) == 0) {
        rsize = fread(ebuf, sizeof(unsigned char), BUFBYTES + MACBYTES, efile);

        r = crypto_secretbox_open_easy(pbuf, ebuf, rsize, n, k);
        if (r != 0) {
            fprintf(stderr, "Could not decrypt data.\n");
            fclose(pfile);
            fclose(efile);
            return FAIL;
        }

        // The decrypted bytes no longer include the MAC bytes.
        wsize = fwrite(pbuf, sizeof(unsigned char), rsize - MACBYTES, pfile);
        if (wsize <= 0)
        {
            fprintf(stderr, "Could not write decrypted data to file.\n");
            fclose(pfile);
            fclose(efile);
            return FAIL;
        }
    }

    fclose(pfile);
    fclose(efile);

    return SUCCESS;
}


/*
* Function: usage
* ---------------
* Write out the usage statement and exit the program.
*/
void usage()
{
    printf("Usage: spud command infile outfile\n");
    printf("Command must be either 'encrypt' or 'decrypt'.\n");
    exit(EXIT_SUCCESS);
}


/*
* Function: get_passphrase
* ------------------------
* Prompt the user for their passphrase. Store it in the buffer represented by
* passphrase. If there is an error, exit the program.
*/
void get_passphrase(char *p)
{
    printf("Enter your passphrase: ");
    fgets(p, PHRASEMAX, stdin);

    if (strlen(p) < PHRASEMIN)
    {
        printf("Passphrase must be at least %d characters.\n", PHRASEMIN);
        exit(EXIT_FAILURE);
    }
}


/*
* Function: get_key_material
* --------------------------
* Attempt to get the needed key material to encrypt or decrypt the file. If
* there is an error, exit the program.
*/
void get_key_material(unsigned char *key, unsigned char *nonce,
                      char *passphrase)
{
    result r;

    r = generate_key_nonce(key, nonce, passphrase);
    if (r == FAIL)
    {
        fprintf(stderr, "Unable to generate key and nonce.\n");
        exit(EXIT_FAILURE);
    }
}


/*
* Function: process_file
* ----------------------
* Attempt to either encrypt or decrypt the infile using the key and nonce
* provided. If there is an error, exit the program.
*/
void process_file(char *command, char *infile, char *outfile,
                  unsigned char *key, unsigned char *nonce)
{
    size_t r = 0;

    if (strcmp(command, "encrypt") == 0)
    {
        r = encrypt_file(infile, outfile, key, nonce);
    } else if (strcmp(command, "decrypt") == 0){
        r = decrypt_file(infile, outfile, key, nonce);
    } else {
        usage();
    }

    if (r == 0)
    {
        printf("Successfully %sed file %s.\n", command, infile);
    } else {
        fprintf(stderr, "Could not %s file %s.\n", command, infile);
        exit(EXIT_FAILURE);
    }
}


/*
* Function: main
* --------------
* Where it all begins.
*/
int main(int argc, char *argv[])
{
    unsigned char key[KEYBYTES] = {0};
    unsigned char nonce[NONCEBYTES] = {0};
    char passphrase[PHRASEMAX] = {0};

    if (argc != 4) { usage(); }

    get_passphrase(passphrase);
    get_key_material(key, nonce, passphrase);
    process_file(argv[1], argv[2], argv[3], key, nonce);

    exit(EXIT_SUCCESS);
}
