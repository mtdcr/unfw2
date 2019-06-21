/*
 * unwfw2 - Extract firmware images of Hue bridges.
 *
 * Copyright 2019 Andreas Oberritter
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Example of usage:
 *   make
 *   ./unfw2 firmware.fw2
 */

#define _GNU_SOURCE
#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>


struct fw2_part {
	unsigned int size_be;
	unsigned short type_be;
	unsigned int zero;
	char version[16];
} __attribute__((packed));

struct fw2_header {
	char product_id[7];
	unsigned char nb_parts;
	unsigned int size_be;
	char description[22];
} __attribute__((packed));


static bool load_pkey(EVP_PKEY **pkey)
{
	EVP_PKEY *ret;
	BIO *bp;

	bp = BIO_new_file("certs/RSA_rel_01_pub.pem", "r");
	if (bp == NULL)
		return false;

	ret = PEM_read_bio_PUBKEY(bp, pkey, NULL, NULL);

	BIO_free(bp);
	return ret != NULL;
}

static bool load_aes_key(unsigned char buf[32])
{
	const char keyfile[] = "certs/enc.k";
	struct stat st;
	ssize_t ret;
	int fd;

	if (stat(keyfile, &st) != 0 ||
	    (st.st_mode & S_IFMT) != S_IFREG ||
	    st.st_size != 32)
		return false;

	fd = open(keyfile, O_RDONLY);
	if (fd < 0) {
		perror(keyfile);
		return false;
	}

	ret = TEMP_FAILURE_RETRY(read(fd, buf, 32));
	if (ret < 0)
		perror("read");

	close(fd);
	return ret == 32;
}

static void save_buf(const char *path, const unsigned char *buf, size_t size, mode_t mode)
{
	FILE *f;

	f = fopen(path, "w");
	assert(f != NULL);
	fwrite(buf, size, 1, f);
	fclose(f);

	chmod(path, mode);
}

static void process_mem(const void *mem, size_t size)
{
	const struct fw2_header *fw = mem;
	const char *version = "Invalid";
	char filename[FILENAME_MAX];
	unsigned int signed_size;
	unsigned char key[32];
	size_t count = 0;

	assert(size >= sizeof(struct fw2_header));
	assert(fw->product_id[sizeof(fw->product_id) - 1] == '\0');
	assert(fw->description[sizeof(fw->description) - 1] == '\0');

	signed_size = be32toh(fw->size_be);

	printf("Product ID: %s\n", fw->product_id);
	printf("Description: %s\n", fw->description);
	printf("Size: %d\n", signed_size);
	assert(size >= signed_size);

	mem += sizeof(struct fw2_header);
	size -= sizeof(struct fw2_header);

	while (count < fw->nb_parts && size > 0) {
		const struct fw2_part *pt = mem;
		unsigned int pt_size = be32toh(pt->size_be);
		unsigned int pt_type = be16toh(pt->type_be);
		size_t offset = mem - (const void *)fw;
		const char *ext = ".bin";

		assert(pt->version[sizeof(pt->version) - 1] == '\0');
		assert(pt->zero == 0);

		version = pt->version;

		printf("--- 8< ---\n");
		printf("Offset: %#lx\n", offset);
		printf("Version: %s\n", version);
		printf("Size: %d\n", pt_size);

		if (pt_type == 0xfe)
			ext = "pem";
		else if (pt_type == 0x103)
			ext = "tgz.aes";

		mem += sizeof(struct fw2_part);
		size -= sizeof(struct fw2_part);

		assert(size >= pt_size);

		if (pt_type == 0x103 && (pt_size & 0xf) == 0 && load_aes_key(key)) {
			EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
			int block_size, decrypt_size, tmp_size;
			void *dest;
			int ret;

			ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, mem);
			assert(ret == 1);

			block_size = EVP_CIPHER_CTX_block_size(ctx);
			decrypt_size = pt_size - block_size;
			dest = malloc(decrypt_size);
			assert(dest != NULL);

			ret = EVP_DecryptUpdate(ctx, dest, &decrypt_size, mem + block_size, decrypt_size);
			assert(ret == 1);
			ret = EVP_DecryptFinal_ex(ctx, dest + decrypt_size, &tmp_size);
			assert(ret == 1);
			decrypt_size += tmp_size;

			EVP_CIPHER_CTX_free(ctx);

			ext = "tgz";
			sprintf(filename, "%s-%s-0x%06zx.%s", fw->product_id, version, offset, ext);
			save_buf(filename, dest, decrypt_size, 0644);
			free(dest);
		} else {
			sprintf(filename, "%s-%s-0x%06zx.%s", fw->product_id, version, offset, ext);
			save_buf(filename, mem, pt_size, 0644);
		}

		mem += pt_size;
		size -= pt_size;

		count++;
	}

	if (size > 0) {
		sprintf(filename, "%s-%s.sig", fw->product_id, version);
		save_buf(filename, mem, size, 0644);

		EVP_PKEY *pkey = NULL;
		if (load_pkey(&pkey)) {
			EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
			int ret = 1;

			assert(size == (size_t)EVP_PKEY_size(pkey));

			ret &= EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey);
			ret &= EVP_DigestVerifyUpdate(mdctx, fw, signed_size);
			ret &= EVP_DigestVerifyFinal(mdctx, mem, EVP_PKEY_size(pkey));

			EVP_MD_CTX_free(mdctx);
			EVP_PKEY_free(pkey);

			printf("--- 8< ---\n");
			printf("Signature: %s\n", (ret == 1) ? "OK" : "Invalid");
		}
	}
}

static bool process_file(int fd)
{
	struct stat st;
	void *mem;

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		return false;
	}

	mem = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		return false;
	}

	process_mem(mem, st.st_size);
	munmap(mem, st.st_size);
	return true;
}

int main(int argc, char *argv[])
{
	bool ok;
	int i;

	for (i = 1; i < argc; i++) {
		int fd = open(argv[i], O_RDONLY);
		if (fd < 0) {
			perror(argv[i]);
			return 1;
		}

		ok = process_file(fd);
		close(fd);
		if (!ok)
			return 1;
	}

	return 0;
}
