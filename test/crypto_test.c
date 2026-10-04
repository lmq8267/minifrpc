/*
 * minifrpc —— 加密基元自测（标准测试向量验证）
 * 编译后运行，全部通过输出"全部通过"。
 */

#include <stdio.h>
#include <string.h>

#include "md5.h"
#include "sha1.h"
#include "kdf.h"
#include "aes.h"

static int g_fail = 0;

static void hex_str(const uint8_t *b, int n, char *out)
{
    static const char h[] = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        out[i * 2] = h[b[i] >> 4];
        out[i * 2 + 1] = h[b[i] & 0xf];
    }
    out[n * 2] = '\0';
}

static void check(const char *name, const uint8_t *got, const char *expect, int n)
{
    char hex[128];
    hex_str(got, n, hex);
    if (strcmp(hex, expect) == 0) {
        printf("[通过] %s = %s\n", name, hex);
    } else {
        printf("[失败] %s = %s (期望 %s)\n", name, hex, expect);
        g_fail++;
    }
}

static void test_md5(void)
{
    uint8_t d[16];
    char out[33];

    md5((const uint8_t *)"", 0, d);
    md5_hex((const uint8_t *)"", 0, out);
    check("MD5(\"\")", d, "d41d8cd98f00b204e9800998ecf8427e", 16);

    md5((const uint8_t *)"abc", 3, d);
    check("MD5(abc)", d, "900150983cd24fb0d6963f7d28e17f72", 16);
}

static void test_sha1(void)
{
    uint8_t d[20];
    sha1((const uint8_t *)"abc", 3, d);
    check("SHA1(abc)", d, "a9993e364706816aba3e25717850c26c9cd0d89d", 20);

    sha1((const uint8_t *)"", 0, d);
    check("SHA1(\"\")", d, "da39a3ee5e6b4b0d3255bfef95601890afd80709", 20);
}

static void test_hmac(void)
{
    uint8_t d[20];
    hmac_sha1((const uint8_t *)"Jefe", 4,
              (const uint8_t *)"what do ya want for nothing?", 28, d);
    check("HMAC-SHA1(Jefe)", d, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79", 20);
}

static void test_pbkdf2(void)
{
    uint8_t d[20];
    pbkdf2_hmac_sha1((const uint8_t *)"password", 8,
                     (const uint8_t *)"salt", 4, 1, d, 20);
    check("PBKDF2(c=1)", d, "0c60c80f961f0e71f3a9b524af6012062fe037a6", 20);

    pbkdf2_hmac_sha1((const uint8_t *)"password", 8,
                     (const uint8_t *)"salt", 4, 2, d, 20);
    check("PBKDF2(c=2)", d, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957", 20);
}

static void test_aes(void)
{
    uint8_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                       0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t pt[16]  = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                       0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    uint8_t ct[16], dec[16];

    aes128_ctx ctx;
    aes128_set_encrypt_key(&ctx, key);
    aes128_encrypt_block(&ctx, pt, ct);
    check("AES128-enc", ct, "69c4e0d86a7b0430d8cdb78070b4c55a", 16);

    aes128_decrypt_block(&ctx, ct, dec);
    if (memcmp(dec, pt, 16) == 0) {
        printf("[通过] AES128-dec 往返一致\n");
    } else {
        printf("[失败] AES128-dec 往返不一致\n");
        g_fail++;
    }
}

static void test_cfb(void)
{
    /* CFB 往返：加密再解密应还原 */
    uint8_t key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t iv[16] = {0};
    uint8_t data[100], enc[100], dec[100];
    for (int i = 0; i < 100; i++) data[i] = (uint8_t)(i * 7 + 3);

    aes_cfb_ctx ec, dc;
    aes_cfb_init(&ec, key, iv);
    aes_cfb_encrypt(&ec, data, enc, 100);

    aes_cfb_init(&dc, key, iv);
    aes_cfb_decrypt(&dc, enc, dec, 100);

    if (memcmp(data, dec, 100) == 0) {
        printf("[通过] CFB128 往返一致\n");
    } else {
        printf("[失败] CFB128 往返不一致\n");
        g_fail++;
    }

    /* CFB 分块流式（跨调用状态保持）验证 */
    uint8_t iv3[16] = {0}, iv4[16] = {0};
    aes_cfb_ctx ec2, dc2;
    aes_cfb_init(&ec2, key, iv3);
    aes_cfb_init(&dc2, key, iv4);
    uint8_t enc2[100], dec2[100];
    /* 分三次加密：7 + 13 + 80 字节 */
    aes_cfb_encrypt(&ec2, data, enc2, 7);
    aes_cfb_encrypt(&ec2, data + 7, enc2 + 7, 13);
    aes_cfb_encrypt(&ec2, data + 20, enc2 + 20, 80);
    /* 分三次解密 */
    aes_cfb_decrypt(&dc2, enc2, dec2, 7);
    aes_cfb_decrypt(&dc2, enc2 + 7, dec2 + 7, 13);
    aes_cfb_decrypt(&dc2, enc2 + 20, dec2 + 20, 80);
    if (memcmp(data, dec2, 100) == 0) {
        printf("[通过] CFB128 分块流式一致\n");
    } else {
        printf("[失败] CFB128 分块流式不一致\n");
        g_fail++;
    }
}

int main(void)
{
    test_md5();
    test_sha1();
    test_hmac();
    test_pbkdf2();
    test_aes();
    test_cfb();

    if (g_fail == 0) {
        printf("\n全部通过\n");
        return 0;
    }
    printf("\n%d 项失败\n", g_fail);
    return 1;
}
