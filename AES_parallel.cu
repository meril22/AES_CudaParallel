
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <cuda.h>
#define BYTE unsigned char

using namespace std;

class aes_block
{
public:
    BYTE block[16];
};

void printBytes(BYTE b[], int len) {
int i;
for (i=0; i<len; i++)
    printf("%x ", b[i]);
printf("\n");
}


void fileOnePrintBytes(BYTE b[], int len, FILE* fp) {
int i;
for (i=0; i<len; i++)
   fprintf(fp, "%02x ", b[i]);
fprintf(fp, "\n");
}


int flag=0;
void fileTwoPrintBytes(BYTE b[], int len, FILE* fp) {
int i;
for (i=0; i<len; i++){
   fprintf(fp, "%c", b[i]);
   if(b[i]=='\n')
        flag++;
   }

}


void fileThreePrintBytes(BYTE b[], int len, FILE* fp) {
int i;
for (i=0; i<len; i++){
 if(b[i]=='\0'){
   return ;
   }
   fprintf(fp, "%c", b[i]);
   if(b[i]=='\n')
        flag++;
   }
}


BYTE SBox[] =
{   /*0    1    2    3    4    5    6    7    8    9    a    b    c    d    e    f */
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76, /*0*/ 
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0, /*1*/
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15, /*2*/
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75, /*3*/
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84, /*4*/
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf, /*5*/
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8, /*6*/ 
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2, /*7*/
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73, /*8*/
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb, /*9*/
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79, /*a*/
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08, /*b*/
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a, /*c*/
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e, /*d*/
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf, /*e*/
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16  /*f*/
};


__device__ void AES_SubBytes(BYTE state[], BYTE sbox[]) {
int i;
for(i = 0; i < 16; i++)
    state[i] = sbox[state[i]];
}

__device__ void AES_AddRoundKey(BYTE state[], BYTE rkey[]) {
    int i;
    for(i = 0; i < 16; i++)
        state[i] ^= rkey[i];
}

__device__ void AES_ShiftRows(BYTE state[], BYTE shifttab[]) {
    BYTE h[16];
    memcpy(h, state, 16);
    int i;
    for(i = 0; i < 16; i++)
        state[i] = h[shifttab[i]];
}

__device__ void AES_MixColumns(BYTE state[], BYTE AES_xtime[]) {
    int i;
    //ared__ BYTE AES_xtime[];
for(i = 0; i < 16; i += 4) {
    BYTE s0 = state[i + 0], s1 = state[i + 1];
    BYTE s2 = state[i + 2], s3 = state[i + 3];
    BYTE h = s0 ^ s1 ^ s2 ^ s3;
    state[i + 0] ^= h ^ AES_xtime[s0 ^ s1];
    state[i + 1] ^= h ^ AES_xtime[s1 ^ s2];
    state[i + 2] ^= h ^ AES_xtime[s2 ^ s3];
    state[i + 3] ^= h ^ AES_xtime[s3 ^ s0];
}
}

__device__ void AES_MixColumns_Inv(BYTE state[], BYTE AES_xtime[]) {
    int i;
    for(i = 0; i < 16; i += 4) {
        BYTE s0 = state[i + 0], s1 = state[i + 1];
        BYTE s2 = state[i + 2], s3 = state[i + 3];
        BYTE h = s0 ^ s1 ^ s2 ^ s3;
        BYTE xh = AES_xtime[h];
        BYTE h1 = AES_xtime[AES_xtime[xh ^ s0 ^ s2]] ^ h;
        BYTE h2 = AES_xtime[AES_xtime[xh ^ s1 ^ s3]] ^ h;
        state[i + 0] ^= h1 ^ AES_xtime[s0 ^ s1];
        state[i + 1] ^= h2 ^ AES_xtime[s1 ^ s2];
        state[i + 2] ^= h1 ^ AES_xtime[s2 ^ s3];
        state[i + 3] ^= h2 ^ AES_xtime[s3 ^ s0];
}
}

__device__ void AES_Init(BYTE SBox[], BYTE AES_ShiftRowTab[], BYTE SBox_Inv[], BYTE AES_xtime[], BYTE AES_ShiftRowTab_Inv[]) {
    // BYTE AES_ShiftRowTab[16] ;
    AES_ShiftRow[0]=0;
    AES_ShiftRow[1]=5;
    AES_ShiftRow[2]=10;
    AES_ShiftRow[3]=15;
    AES_ShiftRow[4]=4;
    AES_ShiftRow[5]=9;
    AES_ShiftRow[6]=14;
    AES_ShiftRow[7]=3;
    AES_ShiftRow[8]=8;
    AES_ShiftRow[9]=13;
    AES_ShiftRow[10]=2;
    AES_ShiftRow[11]=7;
    AES_ShiftRow[12]=12;
    AES_ShiftRow[13]=1;
    AES_ShiftRow[14]=6;
    AES_ShiftRow[15]=11;
    
SBox[0] = 0x63;SBox[1] = 0x7c;SBox[2] = 0x77;SBox[3] = 0x7b;SBox[4] = 0xf2;SBox[5] = 0x6b;SBox[6] = 0x6f;SBox[7] = 0xc5;SBox[8] = 0x30;SBox[9] = 0x1;SBox[10] = 0x67;SBox[11] = 0x2b;SBox[12] = 0xfe;SBox[13] = 0xd7;SBox[14] = 0xab;SBox[15] = 0x76;
SBox[16] = 0xca;SBox[17] = 0x82;SBox[18] = 0xc9;SBox[19] = 0x7d;SBox[20] = 0xfa;SBox[21] = 0x59;SBox[22] = 0x47;SBox[23] = 0xf0;SBox[24] = 0xad;SBox[25] = 0xd4;SBox[26] = 0xa2;SBox[27] = 0xaf;SBox[28] = 0x9c;SBox[29] = 0xa4;SBox[30] = 0x72;SBox[31] = 0xc0;
SBox[32] = 0xb7;SBox[33] = 0xfd;SBox[34] = 0x93;SBox[35] = 0x26;SBox[36] = 0x36;SBox[37] = 0x3f;SBox[38] = 0xf7;SBox[39] = 0xcc;SBox[40] = 0x34;SBox[41] = 0xa5;SBox[42] = 0xe5;SBox[43] = 0xf1;SBox[44] = 0x71;SBox[45] = 0xd8;SBox[46] = 0x31;SBox[47] = 0x15;
SBox[48] = 0x4;SBox[49] = 0xc7;SBox[50] = 0x23;SBox[51] = 0xc3;SBox[52] = 0x18;SBox[53] = 0x96;SBox[54] = 0x5;SBox[55] = 0x9a;SBox[56] = 0x7;SBox[57] = 0x12;SBox[58] = 0x80;SBox[59] = 0xe2;SBox[60] = 0xeb;SBox[61] = 0x27;SBox[62] = 0xb2;SBox[63] = 0x75;
SBox[64] = 0x9;SBox[65] = 0x83;SBox[66] = 0x2c;SBox[67] = 0x1a;SBox[68] = 0x1b;SBox[69] = 0x6e;SBox[70] = 0x5a;SBox[71] = 0xa0;SBox[72] = 0x52;SBox[73] = 0x3b;SBox[74] = 0xd6;SBox[75] = 0xb3;SBox[76] = 0x29;SBox[77] = 0xe3;SBox[78] = 0x2f;SBox[79] = 0x84;
SBox[80] = 0x53;SBox[81] = 0xd1;SBox[82] = 0x0;SBox[83] = 0xed;SBox[84] = 0x20;SBox[85] = 0xfc;SBox[86] = 0xb1;SBox[87] = 0x5b;SBox[88] = 0x6a;SBox[89] = 0xcb;SBox[90] = 0xbe;SBox[91] = 0x39;SBox[92] = 0x4a;SBox[93] = 0x4c;SBox[94] = 0x58;SBox[95] = 0xcf;
SBox[96] = 0xd0;SBox[97] = 0xef;SBox[98] = 0xaa;SBox[99] = 0xfb;SBox[100] = 0x43;SBox[101] = 0x4d;SBox[102] = 0x33;SBox[103] = 0x85;SBox[104] = 0x45;SBox[105] = 0xf9;SBox[106] = 0x2;SBox[107] = 0x7f;SBox[108] = 0x50;SBox[109] = 0x3c;SBox[110] = 0x9f;SBox[111] = 0xa8;
SBox[112] = 0x51;SBox[113] = 0xa3;SBox[114] = 0x40;SBox[115] = 0x8f;SBox[116] = 0x92;SBox[117] = 0x9d;SBox[118] = 0x38;SBox[119] = 0xf5;SBox[120] = 0xbc;SBox[121] = 0xb6;SBox[122] = 0xda;SBox[123] = 0x21;SBox[124] = 0x10;SBox[125] = 0xff;SBox[126] = 0xf3;SBox[127] = 0xd2;
SBox[128] = 0xcd;SBox[129] = 0xc;SBox[130] = 0x13;SBox[131] = 0xec;SBox[132] = 0x5f;SBox[133] = 0x97;SBox[134] = 0x44;SBox[135] = 0x17;SBox[136] = 0xc4;SBox[137] = 0xa7;SBox[138] = 0x7e;SBox[139] = 0x3d;SBox[140] = 0x64;SBox[141] = 0x5d;SBox[142] = 0x19;SBox[143] = 0x73;
SBox[144] = 0x60;SBox[145] = 0x81;SBox[146] = 0x4f;SBox[147] = 0xdc;SBox[148] = 0x22;SBox[149] = 0x2a;SBox[150] = 0x90;SBox[151] = 0x88;SBox[152] = 0x46;SBox[153] = 0xee;SBox[154] = 0xb8;SBox[155] = 0x14;SBox[156] = 0xde;SBox[157] = 0x5e;SBox[158] = 0xb;SBox[159] = 0xdb;
SBox[160] = 0xe0;SBox[161] = 0x32;SBox[162] = 0x3a;SBox[163] = 0xa;SBox[164] = 0x49;SBox[165] = 0x6;SBox[166] = 0x24;SBox[167] = 0x5c;SBox[168] = 0xc2;SBox[169] = 0xd3;SBox[170] = 0xac;SBox[171] = 0x62;SBox[172] = 0x91;SBox[173] = 0x95;SBox[174] = 0xe4;SBox[175] = 0x79;
SBox[176] = 0xe7;SBox[177] = 0xc8;SBox[178] = 0x37;SBox[179] = 0x6d;SBox[180] = 0x8d;SBox[181] = 0xd5;SBox[182] = 0x4e;SBox[183] = 0xa9;SBox[184] = 0x6c;SBox[185] = 0x56;SBox[186] = 0xf4;SBox[187] = 0xea;SBox[188] = 0x65;SBox[189] = 0x7a;SBox[190] = 0xae;SBox[191] = 0x8;
SBox[192] = 0xba;SBox[193] = 0x78;SBox[194] = 0x25;SBox[195] = 0x2e;SBox[196] = 0x1c;SBox[197] = 0xa6;SBox[198] = 0xb4;SBox[199] = 0xc6;SBox[200] = 0xe8;SBox[201] = 0xdd;SBox[202] = 0x74;SBox[203] = 0x1f;SBox[204] = 0x4b;SBox[205] = 0xbd;SBox[206] = 0x8b;SBox[207] = 0x8a;
SBox[208] = 0x70;SBox[209] = 0x3e;SBox[210] = 0xb5;SBox[211] = 0x66;SBox[212] = 0x48;SBox[213] = 0x3;SBox[214] = 0xf6;SBox[215] = 0xe;SBox[216] = 0x61;SBox[217] = 0x35;SBox[218] = 0x57;SBox[219] = 0xb9;SBox[220] = 0x86;SBox[221] = 0xc1;SBox[222] = 0x1d;SBox[223] = 0x9e;
SBox[224] = 0xe1;SBox[225] = 0xf8;SBox[226] = 0x98;SBox[227] = 0x11;SBox[228] = 0x69;SBox[229] = 0xd9;SBox[230] = 0x8e;SBox[231] = 0x94;SBox[232] = 0x9b;SBox[233] = 0x1e;SBox[234] = 0x87;SBox[235] = 0xe9;SBox[236] = 0xce;SBox[237] = 0x55;SBox[238] = 0x28;SBox[239] = 0xdf;
SBox[240] = 0x8c;SBox[241] = 0xa1;SBox[242] = 0x89;SBox[243] = 0xd;SBox[244] = 0xbf;SBox[245] = 0xe6;SBox[246] = 0x42;SBox[247] = 0x68;SBox[248] = 0x41;SBox[249] = 0x99;SBox[250] = 0x2d;SBox[251] = 0xf;SBox[252] = 0xb0;SBox[253] = 0x54;SBox[254] = 0xbb; SBox[255] = 0x16;
   
    int i;
    for(i = 0; i < 256; i++){
        SBox_Inv[SBox[i]] = i;
    }
    for(i = 0; i < 16; i++)
        AES_ShiftRow_Inv[AES_ShiftRow[i]] = i;
    for(i = 0; i < 128; i++) {
        AES_xtime[i] = i << 1;
        AES_xtime[128 + i] = (i << 1) ^ 0x1b;
    }
}

__device__ void AES_Init2(BYTE SBox[], BYTE AES_ShiftRow[], BYTE SBox_Inv[], BYTE AES_xtime[], BYTE AES_ShiftRow_Inv[]) {
    // BYTE AES_ShiftRow[16] ;
    AES_ShiftRow[0]=0;
    AES_ShiftRow[1]=5;
    AES_ShiftRow[2]=10;
    AES_ShiftRow[3]=15;
    AES_ShiftRow[4]=4;
    AES_ShiftRow[5]=9;
    AES_ShiftRow[6]=14;
    AES_ShiftRow[7]=3;
    AES_ShiftRow[8]=8;
    AES_ShiftRow[9]=13;
    AES_ShiftRow[10]=2;
    AES_ShiftRow[11]=7;
    AES_ShiftRow[12]=12;
    AES_ShiftRow[13]=1;
    AES_ShiftRow[14]=6;
    AES_ShiftRow[15]=11;
    

    
SBox_Inv[0] = 0x52;SBox_Inv[1] = 0x9;SBox_Inv[2] = 0x6a;SBox_Inv[3] = 0xd5;SBox_Inv[4] = 0x30;SBox_Inv[5] = 0x36;SBox_Inv[6] = 0xa5;SBox_Inv[7] = 0x38;SBox_Inv[8] = 0xbf;SBox_Inv[9] = 0x40;SBox_Inv[10] = 0xa3;SBox_Inv[11] = 0x9e;SBox_Inv[12] = 0x81;SBox_Inv[13] = 0xf3;SBox_Inv[14] = 0xd7;SBox_Inv[15] = 0xfb;
SBox_Inv[16] = 0x7c;SBox_Inv[17] = 0xe3;SBox_Inv[18] = 0x39;SBox_Inv[19] = 0x82;SBox_Inv[20] = 0x9b;SBox_Inv[21] = 0x2f;SBox_Inv[22] = 0xff;SBox_Inv[23] = 0x87;SBox_Inv[24] = 0x34;SBox_Inv[25] = 0x8e;SBox_Inv[26] = 0x43;SBox_Inv[27] = 0x44;SBox_Inv[28] = 0xc4;SBox_Inv[29] = 0xde;SBox_Inv[30] = 0xe9;SBox_Inv[31] = 0xcb;
SBox_Inv[32] = 0x54;SBox_Inv[33] = 0x7b;SBox_Inv[34] = 0x94;SBox_Inv[35] = 0x32;SBox_Inv[36] = 0xa6;SBox_Inv[37] = 0xc2;SBox_Inv[38] = 0x23;SBox_Inv[39] = 0x3d;SBox_Inv[40] = 0xee;SBox_Inv[41] = 0x4c;SBox_Inv[42] = 0x95;SBox_Inv[43] = 0xb;SBox_Inv[44] = 0x42;SBox_Inv[45] = 0xfa;SBox_Inv[46] = 0xc3;SBox_Inv[47] = 0x4e;
SBox_Inv[48] = 0x8;SBox_Inv[49] = 0x2e;SBox_Inv[50] = 0xa1;SBox_Inv[51] = 0x66;SBox_Inv[52] = 0x28;SBox_Inv[53] = 0xd9;SBox_Inv[54] = 0x24;SBox_Inv[55] = 0xb2;SBox_Inv[56] = 0x76;SBox_Inv[57] = 0x5b;SBox_Inv[58] = 0xa2;SBox_Inv[59] = 0x49;SBox_Inv[60] = 0x6d;SBox_Inv[61] = 0x8b;SBox_Inv[62] = 0xd1;SBox_Inv[63] = 0x25;
SBox_Inv[64] = 0x72;SBox_Inv[65] = 0xf8;SBox_Inv[66] = 0xf6;SBox_Inv[67] = 0x64;SBox_Inv[68] = 0x86;SBox_Inv[69] = 0x68;SBox_Inv[70] = 0x98;SBox_Inv[71] = 0x16;SBox_Inv[72] = 0xd4;SBox_Inv[73] = 0xa4;SBox_Inv[74] = 0x5c;SBox_Inv[75] = 0xcc;SBox_Inv[76] = 0x5d;SBox_Inv[77] = 0x65;SBox_Inv[78] = 0xb6;SBox_Inv[79] = 0x92;
SBox_Inv[80] = 0x6c;SBox_Inv[81] = 0x70;SBox_Inv[82] = 0x48;SBox_Inv[83] = 0x50;SBox_Inv[84] = 0xfd;SBox_Inv[85] = 0xed;SBox_Inv[86] = 0xb9;SBox_Inv[87] = 0xda;SBox_Inv[88] = 0x5e;SBox_Inv[89] = 0x15;SBox_Inv[90] = 0x46;SBox_Inv[91] = 0x57;SBox_Inv[92] = 0xa7;SBox_Inv[93] = 0x8d;SBox_Inv[94] = 0x9d;SBox_Inv[95] = 0x84;
SBox_Inv[96] = 0x90;SBox_Inv[97] = 0xd8;SBox_Inv[98] = 0xab;SBox_Inv[99] = 0x0;SBox_Inv[100] = 0x8c;SBox_Inv[101] = 0xbc;SBox_Inv[102] = 0xd3;SBox_Inv[103] = 0xa;SBox_Inv[104] = 0xf7;SBox_Inv[105] = 0xe4;SBox_Inv[106] = 0x58;SBox_Inv[107] = 0x5;SBox_Inv[108] = 0xb8;SBox_Inv[109] = 0xb3;SBox_Inv[110] = 0x45;SBox_Inv[111] = 0x6;
SBox_Inv[112] = 0xd0;SBox_Inv[113] = 0x2c;SBox_Inv[114] = 0x1e;SBox_Inv[115] = 0x8f;SBox_Inv[116] = 0xca;SBox_Inv[117] = 0x3f;SBox_Inv[118] = 0xf;SBox_Inv[119] = 0x2;SBox_Inv[120] = 0xc1;SBox_Inv[121] = 0xaf;SBox_Inv[122] = 0xbd;SBox_Inv[123] = 0x3;SBox_Inv[124] = 0x1;SBox_Inv[125] = 0x13;SBox_Inv[126] = 0x8a;SBox_Inv[127] = 0x6b;
SBox_Inv[128] = 0x3a;SBox_Inv[129] = 0x91;SBox_Inv[130] = 0x11;SBox_Inv[131] = 0x41;SBox_Inv[132] = 0x4f;SBox_Inv[133] = 0x67;SBox_Inv[134] = 0xdc;SBox_Inv[135] = 0xea;SBox_Inv[136] = 0x97;SBox_Inv[137] = 0xf2;SBox_Inv[138] = 0xcf;SBox_Inv[139] = 0xce;SBox_Inv[140] = 0xf0;SBox_Inv[141] = 0xb4;SBox_Inv[142] = 0xe6;SBox_Inv[143] = 0x73;
SBox_Inv[144] = 0x96;SBox_Inv[145] = 0xac;SBox_Inv[146] = 0x74;SBox_Inv[147] = 0x22;SBox_Inv[148] = 0xe7;SBox_Inv[149] = 0xad;SBox_Inv[150] = 0x35;SBox_Inv[151] = 0x85;SBox_Inv[152] = 0xe2;SBox_Inv[153] = 0xf9;SBox_Inv[154] = 0x37;SBox_Inv[155] = 0xe8;SBox_Inv[156] = 0x1c;SBox_Inv[157] = 0x75;SBox_Inv[158] = 0xdf;SBox_Inv[159] = 0x6e;
SBox_Inv[160] = 0x47;SBox_Inv[161] = 0xf1;SBox_Inv[162] = 0x1a;SBox_Inv[163] = 0x71;SBox_Inv[164] = 0x1d;SBox_Inv[165] = 0x29;SBox_Inv[166] = 0xc5;SBox_Inv[167] = 0x89;SBox_Inv[168] = 0x6f;SBox_Inv[169] = 0xb7;SBox_Inv[170] = 0x62;SBox_Inv[171] = 0xe;SBox_Inv[172] = 0xaa;SBox_Inv[173] = 0x18;SBox_Inv[174] = 0xbe;SBox_Inv[175] = 0x1b;
SBox_Inv[176] = 0xfc;SBox_Inv[177] = 0x56;SBox_Inv[178] = 0x3e;SBox_Inv[179] = 0x4b;SBox_Inv[180] = 0xc6;SBox_Inv[181] = 0xd2;SBox_Inv[182] = 0x79;SBox_Inv[183] = 0x20;SBox_Inv[184] = 0x9a;SBox_Inv[185] = 0xdb;SBox_Inv[186] = 0xc0;SBox_Inv[187] = 0xfe;SBox_Inv[188] = 0x78;SBox_Inv[189] = 0xcd;SBox_Inv[190] = 0x5a;SBox_Inv[191] = 0xf4;
SBox_Inv[192] = 0x1f;SBox_Inv[193] = 0xdd;SBox_Inv[194] = 0xa8;SBox_Inv[195] = 0x33;SBox_Inv[196] = 0x88;SBox_Inv[197] = 0x7;SBox_Inv[198] = 0xc7;SBox_Inv[199] = 0x31;SBox_Inv[200] = 0xb1;SBox_Inv[201] = 0x12;SBox_Inv[202] = 0x10;SBox_Inv[203] = 0x59;SBox_Inv[204] = 0x27;SBox_Inv[205] = 0x80;SBox_Inv[206] = 0xec;SBox_Inv[207] = 0x5f;
SBox_Inv[208] = 0x60;SBox_Inv[209] = 0x51;SBox_Inv[210] = 0x7f;SBox_Inv[211] = 0xa9;SBox_Inv[212] = 0x19;SBox_Inv[213] = 0xb5;SBox_Inv[214] = 0x4a;SBox_Inv[215] = 0xd;SBox_Inv[216] = 0x2d;SBox_Inv[217] = 0xe5;SBox_Inv[218] = 0x7a;SBox_Inv[219] = 0x9f;SBox_Inv[220] = 0x93;SBox_Inv[221] = 0xc9;SBox_Inv[222] = 0x9c;SBox_Inv[223] = 0xef;
SBox_Inv[224] = 0xa0;SBox_Inv[225] = 0xe0;SBox_Inv[226] = 0x3b;SBox_Inv[227] = 0x4d;SBox_Inv[228] = 0xae;SBox_Inv[229] = 0x2a;SBox_Inv[230] = 0xf5;SBox_Inv[231] = 0xb0;SBox_Inv[232] = 0xc8;SBox_Inv[233] = 0xeb;SBox_Inv[234] = 0xbb;SBox_Inv[235] = 0x3c;SBox_Inv[236] = 0x83;SBox_Inv[237] = 0x53;SBox_Inv[238] = 0x99;SBox_Inv[239] = 0x61;
SBox_Inv[240] = 0x17;SBox_Inv[241] = 0x2b;SBox_Inv[242] = 0x4;SBox_Inv[243] = 0x7e;SBox_Inv[244] = 0xba;SBox_Inv[245] = 0x77;SBox_Inv[246] = 0xd6;SBox_Inv[247] = 0x26;SBox_Inv[248] = 0xe1;SBox_Inv[249] = 0x69;SBox_Inv[250] = 0x14;SBox_Inv[251] = 0x63;SBox_Inv[252] = 0x55;SBox_Inv[253] = 0x21;SBox_Inv[254] = 0xc;SBox_Inv[255] = 0x7d;

    int i;
    for(i = 0; i < 16; i++)
        AES_ShiftRow_Inv[AES_ShiftRow[i]] = i;
    for(i = 0; i < 128; i++) {
        AES_xtime[i] = i << 1;
        AES_xtime[128 + i] = (i << 1) ^ 0x1b;
    }
}
 
// Call this function after the last encryption/decryption operation.
void AES_Done() {}


int AES_ExpandKey(BYTE key[], int keyLen) {
    int kl = keyLen, ks, Rcon = 1, i, j;
    BYTE temp[4], temp2[4];
    switch (kl) {
        case 16: ks = 16 * (10 + 1); break;
        case 24: ks = 16 * (12 + 1); break;
        case 32: ks = 16 * (14 + 1); break;
        default: 
        printf("AES_ExpandKey: Only key lengths of 16, 24 or 32 bytes allowed!");
}
    for(i = kl; i < ks; i += 4) {
        memcpy(temp, &key[i-4], 4);
    if (i % kl == 0) {
        temp2[0] = SBox[temp[1]] ^ Rcon;
        temp2[1] = SBox[temp[2]];
        temp2[2] = SBox[temp[3]];
        temp2[3] = SBox[temp[0]];
        memcpy(temp, temp2, 4);
        if ((Rcon <<= 1) >= 256)
            Rcon ^= 0x11b;
}
    else if ((kl > 24) && (i % kl == 16)) {
        temp2[0] = SBox[temp[0]];
        temp2[1] = SBox[temp[1]];
        temp2[2] = SBox[temp[2]];
        temp2[3] = SBox[temp[3]];
        memcpy(temp, temp2, 4);
    }
    for(j = 0; j < 4; j++)
        key[i + j] = key[i + j - kl] ^ temp[j];
    }
    return ks;
}

__global__ void AES_Encrypt(aes_block aes_block_array[], BYTE key[], int keyLen, int block_number) {
    int global_thread_index = blockDim.x*blockIdx.x + threadIdx.x;
    
    __shared__ BYTE AES_ShiftRow[16];
    __shared__ BYTE SBox[256];
    __shared__ BYTE AES_ShiftRow_Inv[16];
    __shared__ BYTE SBox_Inv[256];
    __shared__ BYTE AES_xtime[256];

    if(global_thread_index < block_number){

        if(threadIdx.x == 0 ){
            printf("hello from thread 0\n");
            AES_Init(SBox, AES_ShiftRow, SBox_Inv, AES_xtime, AES_ShiftRow_Inv);
        }
        __syncthreads();
        BYTE block[16]; 

        for(int i=0; i<16; i++){
            block[i] = aes_block_array[global_thread_index].block[i];
        }
        int l = keyLen, i;
        AES_AddRoundKey(block, &key[0]);
        for(i = 16; i < l - 16; i += 16) {
            AES_SubBytes(block, SBox);
           AES_ShiftRows(block, AES_ShiftRow);
           AES_MixColumns(block, AES_xtime);
            AES_AddRoundKey(block, &key[i]);
        }
        AES_SubBytes(block, SBox);
        AES_ShiftRows(block, AES_ShiftRow);
        AES_AddRoundKey(block, &key[i]);

        for(int i=0; i<16; i++){
  
         aes_block_array[global_thread_index].block[i] = block[i];
        }
        
    }
}


__global__ void AES_Decrypt(aes_block aes_block_array[], BYTE key[], int keyLen, int block_number) {
    int global_thread_index = blockDim.x*blockIdx.x + threadIdx.x;
    __shared__ BYTE AES_ShiftRow[16];
    __shared__ BYTE SBox[256];
    __shared__ BYTE AES_ShiftRow_Inv[16];
    __shared__ BYTE SBox_Inv[256];
    __shared__ BYTE AES_xtime[256];

    if(global_thread_index < block_number){

        if(threadIdx.x == 0 ){

            AES_Init2(SBox, AES_ShiftRow, SBox_Inv, AES_xtime, AES_ShiftRow_Inv);
        }
        __syncthreads();
        BYTE block[16]; 
        for(int i=0; i<16; i++){
            block[i] = aes_block_array[global_thread_index].block[i];

        }
int l = keyLen, i;
AES_AddRoundKey(block, &key[l - 16]);
AES_ShiftRows(block, AES_ShiftRow_Inv);
AES_SubBytes(block, SBox_Inv);
for(i = l - 32; i >= 16; i -= 16) {
    AES_AddRoundKey(block, &key[i]);
    AES_MixColumns_Inv(block, AES_xtime);
    AES_ShiftRows(block, AES_ShiftRow_Inv);
AES_SubBytes(block, SBox_Inv);
}
AES_AddRoundKey(block, &key[0]);
        for(int i=0; i<16; i++){

         aes_block_array[global_thread_index].block[i] = block[i];
        }
}
}


// testing
int main(int argc, char* argv[]) {


    ifstream ifs;
    ifs.open(argv[1], std::ifstream::binary);
    if(!ifs){
        cerr<<"Cannot open file"<<endl;
        exit(1);
    }
    ifs.seekg(0, ios::end);
    int infileLength = ifs.tellg();
    ifs.seekg (0, ios::beg);
    cout<<"Length of input file: "<<infileLength<<endl;


int block_number = infileLength/16 ;
int number_of_zero_pending = infileLength%16;
aes_block* aes_block_array;

BYTE key[16 * (14 + 1)];
int keyLen = 0;
,
int blockLen = 16;

ifstream key_fp;
key_fp.open(argv[2]);
while(key_fp.peek()!=EOF)
{
        key_fp>>key[keyLen];
        if(key_fp.eof())
            break;
        keyLen++;
}

cout<<keyLen<<endl;
switch (keyLen)
{
  case 16:break;
  case 24:break;
  case 32:break;
  default:printf("Key length should be 128, 192, 256bits\n"); return 0;
}

int expandKeyLen = AES_ExpandKey(key, keyLen);


if(number_of_zero_pending != 0)
    aes_block_array = new aes_block [ block_number + 1];
else
    aes_block_array = new aes_block[ block_number ];
char temp[16];

FILE* en_fp;
FILE* de_fp;

en_fp = fopen(argv[3], "wb");
de_fp = fopen(argv[4], "wb");
for(int i=0; i<block_number; i++){
    
    ifs.read(temp, 16);
    for(int j=0; j<16; j++){
        aes_block_array[i].block[j] = (unsigned char)temp[j];
    }
}
if(number_of_zero_pending != 0)
{
    ifs.read(temp, number_of_zero_pending);
    for(int j=0; j<16; j++){
        aes_block_array[block_number].block[j] = (unsigned char)temp[j];
    }
    for(int j=1; j<=16-number_of_zero_pending; j++)
        aes_block_array[block_number].block[16-j] = '\0';
    block_number++;
}


cudaSetDevice(0);	
cudaDeviceProp prop;
cudaGetDeviceProperties(&prop, 0);
int num_sm = prop.multiProcessorCount; 

aes_block *cuda_aes_block_array;
BYTE *cuda_key;


int thrdperblock = block_number/num_sm;
if(block_number%num_sm>0)
    thrdperblock++;

if(thrdperblock>1024){
    thrdperblock = 1024;
    num_sm = block_number/1024;
    if(block_number%1024>0){
        num_sm++;
    }
}
dim3 ThreadperBlock(thrdperblock);

printf("\nThreads per block: %d\n", thrdperblock);

dim3 BlockperGrid(num_sm);
cudaMalloc(&cuda_aes_block_array, block_number*sizeof(class aes_block));
cudaMalloc(&cuda_key,16*15*sizeof(BYTE) );
cudaMemcpy(cuda_aes_block_array, aes_block_array, block_number*sizeof(class aes_block), cudaMemcpyHostToDevice);
cudaMemcpy(cuda_key, key, 16*15*sizeof(BYTE), cudaMemcpyHostToDevice);


AES_Encrypt <<< BlockperGrid, ThreadperBlock>>>(cuda_aes_block_array, cuda_key, expandKeyLen, block_number);

cudaMemcpy(aes_block_array, cuda_aes_block_array, block_number*sizeof(class aes_block), cudaMemcpyDeviceToHost);

for(int i=0; i<block_number-1; i++){
    fileOnePrintBytes(aes_block_array[i].block, blockLen, en_fp);
}
if(number_of_zero_pending == 0)
    fileOnePrintBytes(aes_block_array[block_number-1].block, blockLen, en_fp);
else 
    fileOnePrintBytes(aes_block_array[block_number-1].block, blockLen, en_fp);


AES_Decrypt <<< BlockperGrid, ThreadperBlock>>>(cuda_aes_block_array, cuda_key, expandKeyLen, block_number);

cudaMemcpy(aes_block_array, cuda_aes_block_array, block_number*sizeof(class aes_block), cudaMemcpyDeviceToHost);

for(int i=0; i<block_number-1; i++){
    fileTwoPrintBytes(aes_block_array[i].block, blockLen, de_fp);
}
if(number_of_zero_pending == 0)
    fileTwoPrintBytes(aes_block_array[block_number-1].block, blockLen, de_fp);
else 
    fileThreePrintBytes(aes_block_array[block_number-1].block, blockLen, de_fp);


AES_Done();
fclose(en_fp);
fclose(de_fp);

    return 0;
}
