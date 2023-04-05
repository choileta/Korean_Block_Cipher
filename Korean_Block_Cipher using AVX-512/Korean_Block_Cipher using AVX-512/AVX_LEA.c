#include "../Korean_Block_Cipher using AVX-512/AVXCrypto.h"
#include <time.h>

uint8_t long_pt[64 * 1024 * 1024] = { 0, };
uint8_t long_ct[64 * 1024 * 1024] = { 0, };
uint8_t long_key[144 * 1024 * 1024] = { 0, };

void lea_128_avx512(uint8_t* ct, uint8_t* pt, const uint8_t* RK) {
    __m512i x0, x1, x2, x3, tmp;
    x0 = _mm512_setr_epi32(
        *((unsigned int*)pt + 0x00), *((unsigned int*)pt + 0x04), *((unsigned int*)pt + 0x08), *((unsigned int*)pt + 0x0c),
        *((unsigned int*)pt + 0x10), *((unsigned int*)pt + 0x14), *((unsigned int*)pt + 0x18), *((unsigned int*)pt + 0x1c),
        *((unsigned int*)pt + 0x20), *((unsigned int*)pt + 0x24), *((unsigned int*)pt + 0x28), *((unsigned int*)pt + 0x2c),
        *((unsigned int*)pt + 0x30), *((unsigned int*)pt + 0x34), *((unsigned int*)pt + 0x38), *((unsigned int*)pt + 0x3c));

    x1 = _mm512_setr_epi32(
        *((unsigned int*)pt + 0x01), *((unsigned int*)pt + 0x05), *((unsigned int*)pt + 0x09), *((unsigned int*)pt + 0x0d),
        *((unsigned int*)pt + 0x11), *((unsigned int*)pt + 0x15), *((unsigned int*)pt + 0x19), *((unsigned int*)pt + 0x1d),
        *((unsigned int*)pt + 0x21), *((unsigned int*)pt + 0x25), *((unsigned int*)pt + 0x29), *((unsigned int*)pt + 0x2d),
        *((unsigned int*)pt + 0x31), *((unsigned int*)pt + 0x35), *((unsigned int*)pt + 0x39), *((unsigned int*)pt + 0x3d));

    x2 = _mm512_setr_epi32(
        *((unsigned int*)pt + 0x02), *((unsigned int*)pt + 0x06), *((unsigned int*)pt + 0x0a), *((unsigned int*)pt + 0x0e),
        *((unsigned int*)pt + 0x12), *((unsigned int*)pt + 0x16), *((unsigned int*)pt + 0x1a), *((unsigned int*)pt + 0x1e),
        *((unsigned int*)pt + 0x22), *((unsigned int*)pt + 0x26), *((unsigned int*)pt + 0x2a), *((unsigned int*)pt + 0x2e),
        *((unsigned int*)pt + 0x32), *((unsigned int*)pt + 0x36), *((unsigned int*)pt + 0x3a), *((unsigned int*)pt + 0x3e));

    x3 = _mm512_setr_epi32(
        *((unsigned int*)pt + 0x03), *((unsigned int*)pt + 0x07), *((unsigned int*)pt + 0x0b), *((unsigned int*)pt + 0x0f),
        *((unsigned int*)pt + 0x13), *((unsigned int*)pt + 0x17), *((unsigned int*)pt + 0x1b), *((unsigned int*)pt + 0x1f),
        *((unsigned int*)pt + 0x23), *((unsigned int*)pt + 0x27), *((unsigned int*)pt + 0x2b), *((unsigned int*)pt + 0x2f),
        *((unsigned int*)pt + 0x33), *((unsigned int*)pt + 0x37), *((unsigned int*)pt + 0x3b), *((unsigned int*)pt + 0x3f));

    XAR3(x3, x2, tmp, RK[4], RK[5]);
    XAR5(x2, x1, tmp, RK[2], RK[3]);
    XAR9(x1, x0, tmp, RK[0], RK[1]);
    XAR3(x0, x3, tmp, RK[10], RK[11]);
    XAR5(x3, x2, tmp, RK[8], RK[9]);
    XAR9(x2, x1, tmp, RK[6], RK[7]);
    XAR3(x1, x0, tmp, RK[16], RK[17]);
    XAR5(x0, x3, tmp, RK[14], RK[15]);
    XAR9(x3, x2, tmp, RK[12], RK[13]);
    XAR3(x2, x1, tmp, RK[22], RK[23]);
    XAR5(x1, x0, tmp, RK[20], RK[21]);
    XAR9(x0, x3, tmp, RK[18], RK[19]);

    XAR3(x3, x2, tmp, RK[28], RK[29]);
    XAR5(x2, x1, tmp, RK[26], RK[27]);
    XAR9(x1, x0, tmp, RK[24], RK[25]);
    XAR3(x0, x3, tmp, RK[34], RK[35]);
    XAR5(x3, x2, tmp, RK[32], RK[33]);
    XAR9(x2, x1, tmp, RK[30], RK[31]);
    XAR3(x1, x0, tmp, RK[40], RK[41]);
    XAR5(x0, x3, tmp, RK[38], RK[39]);
    XAR9(x3, x2, tmp, RK[36], RK[37]);
    XAR3(x2, x1, tmp, RK[46], RK[47]);
    XAR5(x1, x0, tmp, RK[44], RK[45]);
    XAR9(x0, x3, tmp, RK[42], RK[43]);

    XAR3(x3, x2, tmp, RK[52], RK[53]);
    XAR5(x2, x1, tmp, RK[50], RK[51]);
    XAR9(x1, x0, tmp, RK[48], RK[49]);
    XAR3(x0, x3, tmp, RK[58], RK[59]);
    XAR5(x3, x2, tmp, RK[56], RK[57]);
    XAR9(x2, x1, tmp, RK[54], RK[55]);
    XAR3(x1, x0, tmp, RK[64], RK[65]);
    XAR5(x0, x3, tmp, RK[62], RK[63]);
    XAR9(x3, x2, tmp, RK[60], RK[61]);
    XAR3(x2, x1, tmp, RK[70], RK[71]);
    XAR5(x1, x0, tmp, RK[68], RK[69]);
    XAR9(x0, x3, tmp, RK[66], RK[67]);

    XAR3(x3, x2, tmp, RK[76], RK[77]);
    XAR5(x2, x1, tmp, RK[74], RK[75]);
    XAR9(x1, x0, tmp, RK[72], RK[73]);
    XAR3(x0, x3, tmp, RK[82], RK[83]);
    XAR5(x3, x2, tmp, RK[80], RK[81]);
    XAR9(x2, x1, tmp, RK[78], RK[79]);
    XAR3(x1, x0, tmp, RK[88], RK[89]);
    XAR5(x0, x3, tmp, RK[86], RK[87]);
    XAR9(x3, x2, tmp, RK[84], RK[85]);
    XAR3(x2, x1, tmp, RK[94], RK[95]);
    XAR5(x1, x0, tmp, RK[92], RK[93]);
    XAR9(x0, x3, tmp, RK[90], RK[91]);

    XAR3(x3, x2, tmp, RK[100], RK[101]);
    XAR5(x2, x1, tmp, RK[98], RK[99]);
    XAR9(x1, x0, tmp, RK[96], RK[97]);
    XAR3(x0, x3, tmp, RK[106], RK[107]);
    XAR5(x3, x2, tmp, RK[104], RK[105]);
    XAR9(x2, x1, tmp, RK[102], RK[103]);
    XAR3(x1, x0, tmp, RK[112], RK[113]);
    XAR5(x0, x3, tmp, RK[110], RK[111]);
    XAR9(x3, x2, tmp, RK[108], RK[109]);
    XAR3(x2, x1, tmp, RK[118], RK[119]);
    XAR5(x1, x0, tmp, RK[116], RK[117]);
    XAR9(x0, x3, tmp, RK[114], RK[115]);

    XAR3(x3, x2, tmp, RK[124], RK[125]);
    XAR5(x2, x1, tmp, RK[122], RK[123]);
    XAR9(x1, x0, tmp, RK[120], RK[121]);
    XAR3(x0, x3, tmp, RK[130], RK[131]);
    XAR5(x3, x2, tmp, RK[128], RK[129]);
    XAR9(x2, x1, tmp, RK[126], RK[127]);
    XAR3(x1, x0, tmp, RK[136], RK[137]);
    XAR5(x0, x3, tmp, RK[134], RK[135]);
    XAR9(x3, x2, tmp, RK[132], RK[133]);
    XAR3(x2, x1, tmp, RK[142], RK[143]);
    XAR5(x1, x0, tmp, RK[140], RK[141]);
    XAR9(x0, x3, tmp, RK[138], RK[139]);

    _mm512_storeu_si512((__m512i*)(ct + 0), x0);
    _mm512_storeu_si512((__m512i*)(ct + 64), x1);
    _mm512_storeu_si512((__m512i*)(ct + 128), x2);
    _mm512_storeu_si512((__m512i*)(ct + 192), x3);
}


void lea_192_avx512(uint8_t* ct, uint8_t* pt, const uint8_t* RK) {
    __m512i x0, x1, x2, x3, tmp;
    x0 = _mm512_setr_epi32(
        *((unsigned int*)pt + 0x00), *((unsigned int*)pt + 0x04), *((unsigned int*)pt + 0x08), *((unsigned int*)pt + 0x0c),
        *((unsigned int*)pt + 0x10), *((unsigned int*)pt + 0x14), *((unsigned int*)pt + 0x18), *((unsigned int*)pt + 0x1c),
        *((unsigned int*)pt + 0x20), *((unsigned int*)pt + 0x24), *((unsigned int*)pt + 0x28), *((unsigned int*)pt + 0x2c),
        *((unsigned int*)pt + 0x30), *((unsigned int*)pt + 0x34), *((unsigned int*)pt + 0x38), *((unsigned int*)pt + 0x3c));

    x1 = _mm512_setr_epi32(
        *((unsigned int*)pt + 0x01), *((unsigned int*)pt + 0x05), *((unsigned int*)pt + 0x09), *((unsigned int*)pt + 0x0d),
        *((unsigned int*)pt + 0x11), *((unsigned int*)pt + 0x15), *((unsigned int*)pt + 0x19), *((unsigned int*)pt + 0x1d),
        *((unsigned int*)pt + 0x21), *((unsigned int*)pt + 0x25), *((unsigned int*)pt + 0x29), *((unsigned int*)pt + 0x2d),
        *((unsigned int*)pt + 0x31), *((unsigned int*)pt + 0x35), *((unsigned int*)pt + 0x39), *((unsigned int*)pt + 0x3d));

    x2 = _mm512_setr_epi32(
        *((unsigned int*)pt + 0x02), *((unsigned int*)pt + 0x06), *((unsigned int*)pt + 0x0a), *((unsigned int*)pt + 0x0e),
        *((unsigned int*)pt + 0x12), *((unsigned int*)pt + 0x16), *((unsigned int*)pt + 0x1a), *((unsigned int*)pt + 0x1e),
        *((unsigned int*)pt + 0x22), *((unsigned int*)pt + 0x26), *((unsigned int*)pt + 0x2a), *((unsigned int*)pt + 0x2e),
        *((unsigned int*)pt + 0x32), *((unsigned int*)pt + 0x36), *((unsigned int*)pt + 0x3a), *((unsigned int*)pt + 0x3e));

    x3 = _mm512_setr_epi32(
        *((unsigned int*)pt + 0x03), *((unsigned int*)pt + 0x07), *((unsigned int*)pt + 0x0b), *((unsigned int*)pt + 0x0f),
        *((unsigned int*)pt + 0x13), *((unsigned int*)pt + 0x17), *((unsigned int*)pt + 0x1b), *((unsigned int*)pt + 0x1f),
        *((unsigned int*)pt + 0x23), *((unsigned int*)pt + 0x27), *((unsigned int*)pt + 0x2b), *((unsigned int*)pt + 0x2f),
        *((unsigned int*)pt + 0x33), *((unsigned int*)pt + 0x37), *((unsigned int*)pt + 0x3b), *((unsigned int*)pt + 0x3f));

    XAR3(x3, x2, tmp, RK[4], RK[5]);
    XAR5(x2, x1, tmp, RK[2], RK[3]);
    XAR9(x1, x0, tmp, RK[0], RK[1]);
    XAR3(x0, x3, tmp, RK[10], RK[11]);
    XAR5(x3, x2, tmp, RK[8], RK[9]);
    XAR9(x2, x1, tmp, RK[6], RK[7]);
    XAR3(x1, x0, tmp, RK[16], RK[17]);
    XAR5(x0, x3, tmp, RK[14], RK[15]);
    XAR9(x3, x2, tmp, RK[12], RK[13]);
    XAR3(x2, x1, tmp, RK[22], RK[23]);
    XAR5(x1, x0, tmp, RK[20], RK[21]);
    XAR9(x0, x3, tmp, RK[18], RK[19]);

    XAR3(x3, x2, tmp, RK[28], RK[29]);
    XAR5(x2, x1, tmp, RK[26], RK[27]);
    XAR9(x1, x0, tmp, RK[24], RK[25]);
    XAR3(x0, x3, tmp, RK[34], RK[35]);
    XAR5(x3, x2, tmp, RK[32], RK[33]);
    XAR9(x2, x1, tmp, RK[30], RK[31]);
    XAR3(x1, x0, tmp, RK[40], RK[41]);
    XAR5(x0, x3, tmp, RK[38], RK[39]);
    XAR9(x3, x2, tmp, RK[36], RK[37]);
    XAR3(x2, x1, tmp, RK[46], RK[47]);
    XAR5(x1, x0, tmp, RK[44], RK[45]);
    XAR9(x0, x3, tmp, RK[42], RK[43]);

    XAR3(x3, x2, tmp, RK[52], RK[53]);
    XAR5(x2, x1, tmp, RK[50], RK[51]);
    XAR9(x1, x0, tmp, RK[48], RK[49]);
    XAR3(x0, x3, tmp, RK[58], RK[59]);
    XAR5(x3, x2, tmp, RK[56], RK[57]);
    XAR9(x2, x1, tmp, RK[54], RK[55]);
    XAR3(x1, x0, tmp, RK[64], RK[65]);
    XAR5(x0, x3, tmp, RK[62], RK[63]);
    XAR9(x3, x2, tmp, RK[60], RK[61]);
    XAR3(x2, x1, tmp, RK[70], RK[71]);
    XAR5(x1, x0, tmp, RK[68], RK[69]);
    XAR9(x0, x3, tmp, RK[66], RK[67]);

    XAR3(x3, x2, tmp, RK[76], RK[77]);
    XAR5(x2, x1, tmp, RK[74], RK[75]);
    XAR9(x1, x0, tmp, RK[72], RK[73]);
    XAR3(x0, x3, tmp, RK[82], RK[83]);
    XAR5(x3, x2, tmp, RK[80], RK[81]);
    XAR9(x2, x1, tmp, RK[78], RK[79]);
    XAR3(x1, x0, tmp, RK[88], RK[89]);
    XAR5(x0, x3, tmp, RK[86], RK[87]);
    XAR9(x3, x2, tmp, RK[84], RK[85]);
    XAR3(x2, x1, tmp, RK[94], RK[95]);
    XAR5(x1, x0, tmp, RK[92], RK[93]);
    XAR9(x0, x3, tmp, RK[90], RK[91]);

    XAR3(x3, x2, tmp, RK[100], RK[101]);
    XAR5(x2, x1, tmp, RK[98], RK[99]);
    XAR9(x1, x0, tmp, RK[96], RK[97]);
    XAR3(x0, x3, tmp, RK[106], RK[107]);
    XAR5(x3, x2, tmp, RK[104], RK[105]);
    XAR9(x2, x1, tmp, RK[102], RK[103]);
    XAR3(x1, x0, tmp, RK[112], RK[113]);
    XAR5(x0, x3, tmp, RK[110], RK[111]);
    XAR9(x3, x2, tmp, RK[108], RK[109]);
    XAR3(x2, x1, tmp, RK[118], RK[119]);
    XAR5(x1, x0, tmp, RK[116], RK[117]);
    XAR9(x0, x3, tmp, RK[114], RK[115]);

    XAR3(x3, x2, tmp, RK[124], RK[125]);
    XAR5(x2, x1, tmp, RK[122], RK[123]);
    XAR9(x1, x0, tmp, RK[120], RK[121]);
    XAR3(x0, x3, tmp, RK[130], RK[131]);
    XAR5(x3, x2, tmp, RK[128], RK[129]);
    XAR9(x2, x1, tmp, RK[126], RK[127]);
    XAR3(x1, x0, tmp, RK[136], RK[137]);
    XAR5(x0, x3, tmp, RK[134], RK[135]);
    XAR9(x3, x2, tmp, RK[132], RK[133]);
    XAR3(x2, x1, tmp, RK[142], RK[143]);
    XAR5(x1, x0, tmp, RK[140], RK[141]);
    XAR9(x0, x3, tmp, RK[138], RK[139]);

    XAR3(x3, x2, tmp, RK[124], RK[125]);
    XAR5(x2, x1, tmp, RK[122], RK[123]);
    XAR9(x1, x0, tmp, RK[120], RK[121]);
    XAR3(x0, x3, tmp, RK[130], RK[131]);
    XAR5(x3, x2, tmp, RK[128], RK[129]);
    XAR9(x2, x1, tmp, RK[126], RK[127]);
    XAR3(x1, x0, tmp, RK[136], RK[137]);
    XAR5(x0, x3, tmp, RK[134], RK[135]);
    XAR9(x3, x2, tmp, RK[132], RK[133]);
    XAR3(x2, x1, tmp, RK[142], RK[143]);
    XAR5(x1, x0, tmp, RK[140], RK[141]);
    XAR9(x0, x3, tmp, RK[138], RK[139]);

    _mm512_storeu_si512((__m512i*)(ct + 0), x0);
    _mm512_storeu_si512((__m512i*)(ct + 64), x1);
    _mm512_storeu_si512((__m512i*)(ct + 128), x2);
    _mm512_storeu_si512((__m512i*)(ct + 192), x3);
}


void lea_256_avx512(uint8_t* ct, uint8_t* pt, const uint8_t* RK) {
    __m512i x0, x1, x2, x3, tmp;
    x0 = _mm512_setr_epi32(
        *((unsigned int*)pt + 0x00), *((unsigned int*)pt + 0x04), *((unsigned int*)pt + 0x08), *((unsigned int*)pt + 0x0c),
        *((unsigned int*)pt + 0x10), *((unsigned int*)pt + 0x14), *((unsigned int*)pt + 0x18), *((unsigned int*)pt + 0x1c),
        *((unsigned int*)pt + 0x20), *((unsigned int*)pt + 0x24), *((unsigned int*)pt + 0x28), *((unsigned int*)pt + 0x2c),
        *((unsigned int*)pt + 0x30), *((unsigned int*)pt + 0x34), *((unsigned int*)pt + 0x38), *((unsigned int*)pt + 0x3c));

    x1 = _mm512_setr_epi32(
        *((unsigned int*)pt + 0x01), *((unsigned int*)pt + 0x05), *((unsigned int*)pt + 0x09), *((unsigned int*)pt + 0x0d),
        *((unsigned int*)pt + 0x11), *((unsigned int*)pt + 0x15), *((unsigned int*)pt + 0x19), *((unsigned int*)pt + 0x1d),
        *((unsigned int*)pt + 0x21), *((unsigned int*)pt + 0x25), *((unsigned int*)pt + 0x29), *((unsigned int*)pt + 0x2d),
        *((unsigned int*)pt + 0x31), *((unsigned int*)pt + 0x35), *((unsigned int*)pt + 0x39), *((unsigned int*)pt + 0x3d));

    x2 = _mm512_setr_epi32(
        *((unsigned int*)pt + 0x02), *((unsigned int*)pt + 0x06), *((unsigned int*)pt + 0x0a), *((unsigned int*)pt + 0x0e),
        *((unsigned int*)pt + 0x12), *((unsigned int*)pt + 0x16), *((unsigned int*)pt + 0x1a), *((unsigned int*)pt + 0x1e),
        *((unsigned int*)pt + 0x22), *((unsigned int*)pt + 0x26), *((unsigned int*)pt + 0x2a), *((unsigned int*)pt + 0x2e),
        *((unsigned int*)pt + 0x32), *((unsigned int*)pt + 0x36), *((unsigned int*)pt + 0x3a), *((unsigned int*)pt + 0x3e));

    x3 = _mm512_setr_epi32(
        *((unsigned int*)pt + 0x03), *((unsigned int*)pt + 0x07), *((unsigned int*)pt + 0x0b), *((unsigned int*)pt + 0x0f),
        *((unsigned int*)pt + 0x13), *((unsigned int*)pt + 0x17), *((unsigned int*)pt + 0x1b), *((unsigned int*)pt + 0x1f),
        *((unsigned int*)pt + 0x23), *((unsigned int*)pt + 0x27), *((unsigned int*)pt + 0x2b), *((unsigned int*)pt + 0x2f),
        *((unsigned int*)pt + 0x33), *((unsigned int*)pt + 0x37), *((unsigned int*)pt + 0x3b), *((unsigned int*)pt + 0x3f));

    XAR3(x3, x2, tmp, RK[4], RK[5]);
    XAR5(x2, x1, tmp, RK[2], RK[3]);
    XAR9(x1, x0, tmp, RK[0], RK[1]);
    XAR3(x0, x3, tmp, RK[10], RK[11]);
    XAR5(x3, x2, tmp, RK[8], RK[9]);
    XAR9(x2, x1, tmp, RK[6], RK[7]);
    XAR3(x1, x0, tmp, RK[16], RK[17]);
    XAR5(x0, x3, tmp, RK[14], RK[15]);
    XAR9(x3, x2, tmp, RK[12], RK[13]);
    XAR3(x2, x1, tmp, RK[22], RK[23]);
    XAR5(x1, x0, tmp, RK[20], RK[21]);
    XAR9(x0, x3, tmp, RK[18], RK[19]);

    XAR3(x3, x2, tmp, RK[28], RK[29]);
    XAR5(x2, x1, tmp, RK[26], RK[27]);
    XAR9(x1, x0, tmp, RK[24], RK[25]);
    XAR3(x0, x3, tmp, RK[34], RK[35]);
    XAR5(x3, x2, tmp, RK[32], RK[33]);
    XAR9(x2, x1, tmp, RK[30], RK[31]);
    XAR3(x1, x0, tmp, RK[40], RK[41]);
    XAR5(x0, x3, tmp, RK[38], RK[39]);
    XAR9(x3, x2, tmp, RK[36], RK[37]);
    XAR3(x2, x1, tmp, RK[46], RK[47]);
    XAR5(x1, x0, tmp, RK[44], RK[45]);
    XAR9(x0, x3, tmp, RK[42], RK[43]);

    XAR3(x3, x2, tmp, RK[52], RK[53]);
    XAR5(x2, x1, tmp, RK[50], RK[51]);
    XAR9(x1, x0, tmp, RK[48], RK[49]);
    XAR3(x0, x3, tmp, RK[58], RK[59]);
    XAR5(x3, x2, tmp, RK[56], RK[57]);
    XAR9(x2, x1, tmp, RK[54], RK[55]);
    XAR3(x1, x0, tmp, RK[64], RK[65]);
    XAR5(x0, x3, tmp, RK[62], RK[63]);
    XAR9(x3, x2, tmp, RK[60], RK[61]);
    XAR3(x2, x1, tmp, RK[70], RK[71]);
    XAR5(x1, x0, tmp, RK[68], RK[69]);
    XAR9(x0, x3, tmp, RK[66], RK[67]);

    XAR3(x3, x2, tmp, RK[76], RK[77]);
    XAR5(x2, x1, tmp, RK[74], RK[75]);
    XAR9(x1, x0, tmp, RK[72], RK[73]);
    XAR3(x0, x3, tmp, RK[82], RK[83]);
    XAR5(x3, x2, tmp, RK[80], RK[81]);
    XAR9(x2, x1, tmp, RK[78], RK[79]);
    XAR3(x1, x0, tmp, RK[88], RK[89]);
    XAR5(x0, x3, tmp, RK[86], RK[87]);
    XAR9(x3, x2, tmp, RK[84], RK[85]);
    XAR3(x2, x1, tmp, RK[94], RK[95]);
    XAR5(x1, x0, tmp, RK[92], RK[93]);
    XAR9(x0, x3, tmp, RK[90], RK[91]);

    XAR3(x3, x2, tmp, RK[100], RK[101]);
    XAR5(x2, x1, tmp, RK[98], RK[99]);
    XAR9(x1, x0, tmp, RK[96], RK[97]);
    XAR3(x0, x3, tmp, RK[106], RK[107]);
    XAR5(x3, x2, tmp, RK[104], RK[105]);
    XAR9(x2, x1, tmp, RK[102], RK[103]);
    XAR3(x1, x0, tmp, RK[112], RK[113]);
    XAR5(x0, x3, tmp, RK[110], RK[111]);
    XAR9(x3, x2, tmp, RK[108], RK[109]);
    XAR3(x2, x1, tmp, RK[118], RK[119]);
    XAR5(x1, x0, tmp, RK[116], RK[117]);
    XAR9(x0, x3, tmp, RK[114], RK[115]);

    XAR3(x3, x2, tmp, RK[124], RK[125]);
    XAR5(x2, x1, tmp, RK[122], RK[123]);
    XAR9(x1, x0, tmp, RK[120], RK[121]);
    XAR3(x0, x3, tmp, RK[130], RK[131]);
    XAR5(x3, x2, tmp, RK[128], RK[129]);
    XAR9(x2, x1, tmp, RK[126], RK[127]);
    XAR3(x1, x0, tmp, RK[136], RK[137]);
    XAR5(x0, x3, tmp, RK[134], RK[135]);
    XAR9(x3, x2, tmp, RK[132], RK[133]);
    XAR3(x2, x1, tmp, RK[142], RK[143]);
    XAR5(x1, x0, tmp, RK[140], RK[141]);
    XAR9(x0, x3, tmp, RK[138], RK[139]);

    XAR3(x3, x2, tmp, RK[124], RK[125]);
    XAR5(x2, x1, tmp, RK[122], RK[123]);
    XAR9(x1, x0, tmp, RK[120], RK[121]);
    XAR3(x0, x3, tmp, RK[130], RK[131]);
    XAR5(x3, x2, tmp, RK[128], RK[129]);
    XAR9(x2, x1, tmp, RK[126], RK[127]);
    XAR3(x1, x0, tmp, RK[136], RK[137]);
    XAR5(x0, x3, tmp, RK[134], RK[135]);
    XAR9(x3, x2, tmp, RK[132], RK[133]);
    XAR3(x2, x1, tmp, RK[142], RK[143]);
    XAR5(x1, x0, tmp, RK[140], RK[141]);
    XAR9(x0, x3, tmp, RK[138], RK[139]);

    XAR3(x3, x2, tmp, RK[124], RK[125]);
    XAR5(x2, x1, tmp, RK[122], RK[123]);
    XAR9(x1, x0, tmp, RK[120], RK[121]);
    XAR3(x0, x3, tmp, RK[130], RK[131]);
    XAR5(x3, x2, tmp, RK[128], RK[129]);
    XAR9(x2, x1, tmp, RK[126], RK[127]);
    XAR3(x1, x0, tmp, RK[136], RK[137]);
    XAR5(x0, x3, tmp, RK[134], RK[135]);
    XAR9(x3, x2, tmp, RK[132], RK[133]);
    XAR3(x2, x1, tmp, RK[142], RK[143]);
    XAR5(x1, x0, tmp, RK[140], RK[141]);
    XAR9(x0, x3, tmp, RK[138], RK[139]);

    _mm512_storeu_si512((__m512i*)(ct + 0), x0);
    _mm512_storeu_si512((__m512i*)(ct + 64), x1);
    _mm512_storeu_si512((__m512i*)(ct + 128), x2);
    _mm512_storeu_si512((__m512i*)(ct + 192), x3);
}

void test_longmsg() {
    uint64_t cycle = 0;
    uint64_t start, end;
    for (int i = 0; i < 100; i++) {
        start = cpucycles();
        for (int j = 0; j < 131072; j++)
            lea_128_avx512(long_ct + 256 * j, long_pt + 256 * j, long_key + 256 * j);
        end = cpucycles();
        cycle += end - start;
    }
    printf("long msg LEA 128 cycle = %lld\n", cycle);

    cycle = 0;
    for (int i = 0; i < 100; i++) {
        start = cpucycles();
        for (int j = 0; j < 131072; j++)
            lea_192_avx512(long_ct + 256 * j, long_pt + 256 * j, long_key + 256 * j);
        end = cpucycles();
        cycle += end - start;
    }
    printf("long msg LEA 192 cycle = %lld\n", cycle);

    cycle = 0;
    for (int i = 0; i < 100; i++) {
        start = cpucycles();
        for (int j = 0; j < 131072; j++)
            lea_256_avx512(long_ct + 256 * j, long_pt + 256 * j, long_key + 256 * j);
        end = cpucycles();
        cycle += end - start;
    }
    printf("long msg LEA 256 cycle = %lld\n", cycle);
}
