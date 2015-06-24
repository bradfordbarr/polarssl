#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "polarssl/config.h"
#include "polarssl/md.h"
#include "polarssl/rsa.h"
#include "polarssl/sha2.h"

/** Private Key Buffers **/
extern uint8_t N[];
extern uint8_t E[];

/** Private Key Buffer Lengths **/
extern uint32_t N_LENGTH;
extern uint32_t E_LENGTH;

rsa_context rsa_ctx;
sha2_context sha256_ctx;

int initialize_rsa() {
  rsa_init(&rsa_ctx, RSA_PKCS_V21, POLARSSL_MD_SHA256);
  mpi_read_binary(&rsa_ctx.N, (unsigned char *)&N, (size_t)N_LENGTH);
  mpi_read_binary(&rsa_ctx.E, (unsigned char *)&E, (size_t)E_LENGTH);
  rsa_ctx.len = 128;
  return 0;
}

void calculate_sha256(uint8_t *buffer, uint32_t length, uint8_t *sha256_hash) {
  sha2_starts(&sha256_ctx, 0);
  sha2_update(&sha256_ctx, buffer, length);
  sha2_finish(&sha256_ctx, sha256_hash);
}

int main(int argc, char **argv) {
  int ret;
  uint8_t sha256_hash[32];
  if (argc < 3) {
    fprintf(stderr, "usage: verify <file-name> <signature>\n");
    exit(1);
  }

  initialize_rsa();

  FILE *file_to_hash;
  uint32_t file_to_hash_length;
  if (NULL == (file_to_hash = fopen(argv[1], "rb"))) {
    fprintf(stderr, "Could not open hash file\n");
    exit(1);
  }
  fseek(file_to_hash, 0, SEEK_END);
  file_to_hash_length = (uint32_t)ftell(file_to_hash);
  rewind(file_to_hash);

  uint8_t *file_to_hash_buffer;
  file_to_hash_buffer = (uint8_t *)malloc((file_to_hash_length+1) * sizeof(uint8_t));
  fread(file_to_hash_buffer, file_to_hash_length, 1, file_to_hash);
  fclose(file_to_hash);

  FILE *signature_file;
  uint32_t signature_length;
  if (NULL == (signature_file = fopen(argv[2], "rb"))) {
    fprintf(stderr, "Could not open signature file\n");
    exit(1);
  }
  fseek(signature_file, 0, SEEK_END);
  signature_length = (uint32_t)ftell(signature_file);
  rewind(signature_file);

  uint8_t *signature_buffer;
  signature_buffer = (uint8_t *)malloc((signature_length+1) * sizeof(uint8_t));
  fread(signature_buffer, signature_length, 1, signature_file);
  fclose(signature_file);

  calculate_sha256(file_to_hash_buffer, file_to_hash_length, sha256_hash);

  if (0 != (ret = rsa_check_pubkey(&rsa_ctx))) {
    fprintf(stderr, "PUBKEY CHECK ERROR: -0x%02X\n", -ret);
    exit(1);
  }

  if (0 != (ret = rsa_pkcs1_verify(&rsa_ctx, RSA_PUBLIC, SIG_RSA_SHA256, 32, sha256_hash, signature_buffer))) {
    fprintf(stderr, "VERIFY ERROR: -0x%02X\n", -ret);
    exit(1);
  }

  free(file_to_hash_buffer);
  free(signature_buffer);

  return 0;
}
