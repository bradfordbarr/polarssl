#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "polarssl/config.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/entropy.h"
#include "polarssl/md.h"
#include "polarssl/rsa.h"
#include "polarssl/sha2.h"

/** Private Key Buffers **/
extern uint8_t N[];
extern uint8_t E[];
extern uint8_t D[];
extern uint8_t P[];
extern uint8_t Q[];
extern uint8_t DP[];
extern uint8_t DQ[];
extern uint8_t QP[];

/** Private Key Buffer Lengths **/
extern uint32_t N_LENGTH;
extern uint32_t E_LENGTH;
extern uint32_t D_LENGTH;
extern uint32_t P_LENGTH;
extern uint32_t Q_LENGTH;
extern uint32_t DP_LENGTH;
extern uint32_t DQ_LENGTH;
extern uint32_t QP_LENGTH;

rsa_context rsa_ctx;
sha2_context sha256_ctx;
entropy_context entropy_ctx;
ctr_drbg_context ctr_drbg_ctx;

int initialize_rsa() {
  rsa_init(&rsa_ctx, RSA_PKCS_V21, POLARSSL_MD_SHA256);
  mpi_read_binary(&rsa_ctx.N, (unsigned char *)&N, (size_t)N_LENGTH);
  mpi_read_binary(&rsa_ctx.E, (unsigned char *)&E, (size_t)E_LENGTH);
  mpi_read_binary(&rsa_ctx.D, (unsigned char *)&D, (size_t)D_LENGTH);
  mpi_read_binary(&rsa_ctx.P, (unsigned char *)&P, (size_t)P_LENGTH);
  mpi_read_binary(&rsa_ctx.Q, (unsigned char *)&Q, (size_t)Q_LENGTH);
  mpi_read_binary(&rsa_ctx.DP, (unsigned char *)&DP, (size_t)DP_LENGTH);
  mpi_read_binary(&rsa_ctx.DQ, (unsigned char *)&DQ, (size_t)DQ_LENGTH);
  mpi_read_binary(&rsa_ctx.QP, (unsigned char *)&QP, (size_t)QP_LENGTH);
  rsa_ctx.len = 128;
  return 0;
}

int initialize_random() {
  entropy_init(&entropy_ctx);
  return ctr_drbg_init(&ctr_drbg_ctx, entropy_func, &entropy_ctx, NULL, 0);
}

void calculate_sha256(uint8_t *buffer, uint32_t length, uint8_t *sha256_hash) {
  sha2_starts(&sha256_ctx, 0);
  sha2_update(&sha256_ctx, buffer, length);
  sha2_finish(&sha256_ctx, sha256_hash);
}

int main(int argc, char **argv) {
  int err;
  uint8_t sha256_hash[32];
  if (argc < 2) {
    fprintf(stderr, "usage: sign <file-name>\n");
    exit(1);
  }

  initialize_rsa();
  initialize_random();

  FILE *in_file;
  uint32_t file_length;
  if (NULL == (in_file = fopen(argv[1], "rb"))) {
    fprintf(stderr, "Could not open file\n");
    exit(1);
  }
  fseek(in_file, 0, SEEK_END);
  file_length = (uint32_t)ftell(in_file);
  rewind(in_file);

  uint8_t *buffer;
  buffer = (uint8_t *)malloc((file_length+1) * sizeof(uint8_t));
  fread(buffer, file_length, 1, in_file);
  fclose(in_file);

  calculate_sha256(buffer, file_length, sha256_hash);
  free(buffer);

  if (0 != (err = rsa_check_privkey(&rsa_ctx))) {
    fprintf(stderr, "PRIVKEY CHECK ERROR: -0x%02X\n", -err);
    exit(1);
  }

  uint8_t signature[128] = { 0 };
  if (0 != (err = rsa_pkcs1_sign(&rsa_ctx, ctr_drbg_random, &ctr_drbg_ctx, RSA_PRIVATE, SIG_RSA_SHA256, 32, sha256_hash, signature))) {
    fprintf(stderr, "SIGN ERROR: -0x%02X\n", -err);
    exit(1);
  }

  printf("%s", signature);
  return 0;
}
