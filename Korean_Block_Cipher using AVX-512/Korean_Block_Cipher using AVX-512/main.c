#include <stdint.h>
#include <stdio.h>
#include <intrin.h>
#include "lea.h"
#include "lea_locl.h"


static uint8_t long_pt[64 * 1024 * 1024] = { 0, };
static uint8_t long_ct[64 * 1024 * 1024] = { 0, };
static uint8_t long_key[144 * 1024 * 1024] = { 0, };

static __int64 cpucycles() {
    return __rdtsc();
}

void lea_encrypt(unsigned char* ct, const unsigned char* pt, const LEA_KEY* key)
{
    unsigned int X0, X1, X2, X3;

    const unsigned int* _pt = (const unsigned int*)pt;
    unsigned int* _ct = (unsigned int*)ct;

    X0 = loadU32(_pt[0]);
    X1 = loadU32(_pt[1]);
    X2 = loadU32(_pt[2]);
    X3 = loadU32(_pt[3]);

    X3 = ROR((X2 ^ key->rk[4]) + (X3 ^ key->rk[5]), 3);
    X2 = ROR((X1 ^ key->rk[2]) + (X2 ^ key->rk[3]), 5);
    X1 = ROL((X0 ^ key->rk[0]) + (X1 ^ key->rk[1]), 9);
    X0 = ROR((X3 ^ key->rk[10]) + (X0 ^ key->rk[11]), 3);
    X3 = ROR((X2 ^ key->rk[8]) + (X3 ^ key->rk[9]), 5);
    X2 = ROL((X1 ^ key->rk[6]) + (X2 ^ key->rk[7]), 9);
    X1 = ROR((X0 ^ key->rk[16]) + (X1 ^ key->rk[17]), 3);
    X0 = ROR((X3 ^ key->rk[14]) + (X0 ^ key->rk[15]), 5);
    X3 = ROL((X2 ^ key->rk[12]) + (X3 ^ key->rk[13]), 9);
    X2 = ROR((X1 ^ key->rk[22]) + (X2 ^ key->rk[23]), 3);
    X1 = ROR((X0 ^ key->rk[20]) + (X1 ^ key->rk[21]), 5);
    X0 = ROL((X3 ^ key->rk[18]) + (X0 ^ key->rk[19]), 9);

    X3 = ROR((X2 ^ key->rk[28]) + (X3 ^ key->rk[29]), 3);
    X2 = ROR((X1 ^ key->rk[26]) + (X2 ^ key->rk[27]), 5);
    X1 = ROL((X0 ^ key->rk[24]) + (X1 ^ key->rk[25]), 9);
    X0 = ROR((X3 ^ key->rk[34]) + (X0 ^ key->rk[35]), 3);
    X3 = ROR((X2 ^ key->rk[32]) + (X3 ^ key->rk[33]), 5);
    X2 = ROL((X1 ^ key->rk[30]) + (X2 ^ key->rk[31]), 9);
    X1 = ROR((X0 ^ key->rk[40]) + (X1 ^ key->rk[41]), 3);
    X0 = ROR((X3 ^ key->rk[38]) + (X0 ^ key->rk[39]), 5);
    X3 = ROL((X2 ^ key->rk[36]) + (X3 ^ key->rk[37]), 9);
    X2 = ROR((X1 ^ key->rk[46]) + (X2 ^ key->rk[47]), 3);
    X1 = ROR((X0 ^ key->rk[44]) + (X1 ^ key->rk[45]), 5);
    X0 = ROL((X3 ^ key->rk[42]) + (X0 ^ key->rk[43]), 9);

    X3 = ROR((X2 ^ key->rk[52]) + (X3 ^ key->rk[53]), 3);
    X2 = ROR((X1 ^ key->rk[50]) + (X2 ^ key->rk[51]), 5);
    X1 = ROL((X0 ^ key->rk[48]) + (X1 ^ key->rk[49]), 9);
    X0 = ROR((X3 ^ key->rk[58]) + (X0 ^ key->rk[59]), 3);
    X3 = ROR((X2 ^ key->rk[56]) + (X3 ^ key->rk[57]), 5);
    X2 = ROL((X1 ^ key->rk[54]) + (X2 ^ key->rk[55]), 9);
    X1 = ROR((X0 ^ key->rk[64]) + (X1 ^ key->rk[65]), 3);
    X0 = ROR((X3 ^ key->rk[62]) + (X0 ^ key->rk[63]), 5);
    X3 = ROL((X2 ^ key->rk[60]) + (X3 ^ key->rk[61]), 9);
    X2 = ROR((X1 ^ key->rk[70]) + (X2 ^ key->rk[71]), 3);
    X1 = ROR((X0 ^ key->rk[68]) + (X1 ^ key->rk[69]), 5);
    X0 = ROL((X3 ^ key->rk[66]) + (X0 ^ key->rk[67]), 9);

    X3 = ROR((X2 ^ key->rk[76]) + (X3 ^ key->rk[77]), 3);
    X2 = ROR((X1 ^ key->rk[74]) + (X2 ^ key->rk[75]), 5);
    X1 = ROL((X0 ^ key->rk[72]) + (X1 ^ key->rk[73]), 9);
    X0 = ROR((X3 ^ key->rk[82]) + (X0 ^ key->rk[83]), 3);
    X3 = ROR((X2 ^ key->rk[80]) + (X3 ^ key->rk[81]), 5);
    X2 = ROL((X1 ^ key->rk[78]) + (X2 ^ key->rk[79]), 9);
    X1 = ROR((X0 ^ key->rk[88]) + (X1 ^ key->rk[89]), 3);
    X0 = ROR((X3 ^ key->rk[86]) + (X0 ^ key->rk[87]), 5);
    X3 = ROL((X2 ^ key->rk[84]) + (X3 ^ key->rk[85]), 9);
    X2 = ROR((X1 ^ key->rk[94]) + (X2 ^ key->rk[95]), 3);
    X1 = ROR((X0 ^ key->rk[92]) + (X1 ^ key->rk[93]), 5);
    X0 = ROL((X3 ^ key->rk[90]) + (X0 ^ key->rk[91]), 9);

    X3 = ROR((X2 ^ key->rk[100]) + (X3 ^ key->rk[101]), 3);
    X2 = ROR((X1 ^ key->rk[98]) + (X2 ^ key->rk[99]), 5);
    X1 = ROL((X0 ^ key->rk[96]) + (X1 ^ key->rk[97]), 9);
    X0 = ROR((X3 ^ key->rk[106]) + (X0 ^ key->rk[107]), 3);
    X3 = ROR((X2 ^ key->rk[104]) + (X3 ^ key->rk[105]), 5);
    X2 = ROL((X1 ^ key->rk[102]) + (X2 ^ key->rk[103]), 9);
    X1 = ROR((X0 ^ key->rk[112]) + (X1 ^ key->rk[113]), 3);
    X0 = ROR((X3 ^ key->rk[110]) + (X0 ^ key->rk[111]), 5);
    X3 = ROL((X2 ^ key->rk[108]) + (X3 ^ key->rk[109]), 9);
    X2 = ROR((X1 ^ key->rk[118]) + (X2 ^ key->rk[119]), 3);
    X1 = ROR((X0 ^ key->rk[116]) + (X1 ^ key->rk[117]), 5);
    X0 = ROL((X3 ^ key->rk[114]) + (X0 ^ key->rk[115]), 9);

    X3 = ROR((X2 ^ key->rk[124]) + (X3 ^ key->rk[125]), 3);
    X2 = ROR((X1 ^ key->rk[122]) + (X2 ^ key->rk[123]), 5);
    X1 = ROL((X0 ^ key->rk[120]) + (X1 ^ key->rk[121]), 9);
    X0 = ROR((X3 ^ key->rk[130]) + (X0 ^ key->rk[131]), 3);
    X3 = ROR((X2 ^ key->rk[128]) + (X3 ^ key->rk[129]), 5);
    X2 = ROL((X1 ^ key->rk[126]) + (X2 ^ key->rk[127]), 9);
    X1 = ROR((X0 ^ key->rk[136]) + (X1 ^ key->rk[137]), 3);
    X0 = ROR((X3 ^ key->rk[134]) + (X0 ^ key->rk[135]), 5);
    X3 = ROL((X2 ^ key->rk[132]) + (X3 ^ key->rk[133]), 9);
    X2 = ROR((X1 ^ key->rk[142]) + (X2 ^ key->rk[143]), 3);
    X1 = ROR((X0 ^ key->rk[140]) + (X1 ^ key->rk[141]), 5);
    X0 = ROL((X3 ^ key->rk[138]) + (X0 ^ key->rk[139]), 9);

    if (key->round > 24)
    {
        X3 = ROR((X2 ^ key->rk[148]) + (X3 ^ key->rk[149]), 3);
        X2 = ROR((X1 ^ key->rk[146]) + (X2 ^ key->rk[147]), 5);
        X1 = ROL((X0 ^ key->rk[144]) + (X1 ^ key->rk[145]), 9);
        X0 = ROR((X3 ^ key->rk[154]) + (X0 ^ key->rk[155]), 3);
        X3 = ROR((X2 ^ key->rk[152]) + (X3 ^ key->rk[153]), 5);
        X2 = ROL((X1 ^ key->rk[150]) + (X2 ^ key->rk[151]), 9);
        X1 = ROR((X0 ^ key->rk[160]) + (X1 ^ key->rk[161]), 3);
        X0 = ROR((X3 ^ key->rk[158]) + (X0 ^ key->rk[159]), 5);
        X3 = ROL((X2 ^ key->rk[156]) + (X3 ^ key->rk[157]), 9);
        X2 = ROR((X1 ^ key->rk[166]) + (X2 ^ key->rk[167]), 3);
        X1 = ROR((X0 ^ key->rk[164]) + (X1 ^ key->rk[165]), 5);
        X0 = ROL((X3 ^ key->rk[162]) + (X0 ^ key->rk[163]), 9);
    }

    if (key->round > 28)
    {
        X3 = ROR((X2 ^ key->rk[172]) + (X3 ^ key->rk[173]), 3);
        X2 = ROR((X1 ^ key->rk[170]) + (X2 ^ key->rk[171]), 5);
        X1 = ROL((X0 ^ key->rk[168]) + (X1 ^ key->rk[169]), 9);
        X0 = ROR((X3 ^ key->rk[178]) + (X0 ^ key->rk[179]), 3);
        X3 = ROR((X2 ^ key->rk[176]) + (X3 ^ key->rk[177]), 5);
        X2 = ROL((X1 ^ key->rk[174]) + (X2 ^ key->rk[175]), 9);
        X1 = ROR((X0 ^ key->rk[184]) + (X1 ^ key->rk[185]), 3);
        X0 = ROR((X3 ^ key->rk[182]) + (X0 ^ key->rk[183]), 5);
        X3 = ROL((X2 ^ key->rk[180]) + (X3 ^ key->rk[181]), 9);
        X2 = ROR((X1 ^ key->rk[190]) + (X2 ^ key->rk[191]), 3);
        X1 = ROR((X0 ^ key->rk[188]) + (X1 ^ key->rk[189]), 5);
        X0 = ROL((X3 ^ key->rk[186]) + (X0 ^ key->rk[187]), 9);
    }

    _ct[0] = loadU32(X0);
    _ct[1] = loadU32(X1);
    _ct[2] = loadU32(X2);
    _ct[3] = loadU32(X3);
}

void test() {
    uint8_t pt[512] = { 0, };
    uint8_t ct[512] = { 0, };
    uint8_t rk[128] = { 0, };
    uint8_t pt16[512] = { 0, };
    uint8_t ct16[512] = { 0, };
    LEA_KEY mk = { 0, };
    uint64_t start, end;

    //srand(time(NULL));

    printf("enc start....\n");
    uint64_t cycle1 = 0;
    for (int i = 0; i < 10000; i++) {
        start = cpucycles();
        lea_encrypt(ct, pt, rk);
        end = cpucycles();
        cycle1 += end - start;
    }
    printf("Cycle LEA 128 cpb= %lf\n", ((float)(cycle1) / (10000 * 16)));

    cycle1 = 0;
    mk.round = 28;
    for (int i = 0; i < 10000; i++) {
        start = cpucycles();
        lea_encrypt(ct, pt, rk);
        end = cpucycles();
        cycle1 += end - start;
    }
    printf("Cycle LEA 192 cpb= %lf\n", ((float)(cycle1) / (10000 * 16)));

    cycle1 = 0;
    mk.round = 32;
    for (int i = 0; i < 10000; i++) {
        start = cpucycles();
        lea_encrypt(ct, pt, rk);
        end = cpucycles();
        cycle1 += end - start;
    }
    printf("Cycle LEA 256 cpb= %lf\n", ((float)(cycle1) / (10000 * 16)));

}

void test_long() {
    uint64_t cycle = 0;
    uint64_t start, end;
    LEA_KEY mk = { 0, };
    mk.round = 24;

    for (int i = 0; i < 10000; i++) {
        start = cpucycles();
        for (int j = 0; j < 1; j++)
            lea_encrypt(long_ct + 16 * j, long_pt + 16 * j, &mk);
        end = cpucycles();
        cycle += end - start;
    }
    printf("long msg LEA 128 cycle = %lld\n", cycle);

    cycle = 0;
    mk.round = 28;
    for (int i = 0; i < 10000; i++) {
        start = cpucycles();
        for (int j = 0; j < 1; j++)
            lea_encrypt(long_ct + 16 * j, long_pt + 16 * j, &mk);
        end = cpucycles();
        cycle += end - start;
    }
    printf("long msg LEA 192 cycle = %lld\n", cycle);

    cycle = 0;
    mk.round = 32;
    for (int i = 0; i < 10000; i++) {
        start = cpucycles();
        for (int j = 0; j < 1; j++)
            lea_encrypt(long_ct + 16 * j, long_pt + 16 * j, &mk);
        end = cpucycles();
        cycle += end - start;
    }
    printf("long msg LEA 256 cycle = %lld\n", cycle);
}

int main() {
    test_long();
    return 0;
}