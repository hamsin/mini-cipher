#ifndef CRYPTO_H_
#define CRYPTO_H_

// encryption/decryption functions
void heys_encrypt(unsigned short &ct,unsigned short* key,unsigned short nc);
void heys_decrypt(unsigned short &ct,unsigned short* key,unsigned short nc);
void heys_encrypt_it(unsigned short &ct,unsigned short* key,unsigned short nc);
void heys_decrypt_it(unsigned short &ct,unsigned short* key,unsigned short nc);
void heys_encrypt_it_ft(unsigned short &ct,unsigned short* key,unsigned short nc);
void heys_decrypt_it_ft(unsigned short &ct,unsigned short* key,unsigned short nc);
void heys_encrypt_lat_it(unsigned short &ct,unsigned short* key,unsigned short nc);
void heys_decrypt_lat_it(unsigned short &ct,unsigned short* key,unsigned short nc);
void heys_encrypt_lat_ft(unsigned short &ct,unsigned short* key,unsigned short nc);
void heys_decrypt_lat_ft(unsigned short &ct,unsigned short* key,unsigned short nc);
void heys_encrypt_lat_it_ft(unsigned short &ct,unsigned short* key,unsigned short nc);
void heys_decrypt_lat_it_ft(unsigned short &ct,unsigned short* key,unsigned short nc);
void heys_encrypt_cbc_it(unsigned short &ct,unsigned short* key,unsigned short nc);
void heys_decrypt_cbc_it(unsigned short &ct,unsigned short* key,unsigned short nc);
void heys_encrypt_cbc_ft(unsigned short &ct,unsigned short* key,unsigned short nc);
void heys_decrypt_cbc_ft(unsigned short &ct,unsigned short* key,unsigned short nc);
void heys_encrypt_cbc(unsigned short &ct,unsigned short* key,unsigned short nc);
void heys_decrypt_cbc(unsigned short &ct,unsigned short* key,unsigned short nc);
void CMS_encrypt(unsigned short &ct,unsigned short* key,unsigned short nc);
void CMS_decrypt(unsigned short &ct,unsigned short* key,unsigned short nc);

// Linear part of ciphers
// Based on Rijndael
void MixColumn_Full_Text(unsigned short &state);
void iMixColumn_Full_Text(unsigned short &state);
void MixColumn_ShiftRow_GF24(unsigned short &state);
void iMixColumn_ShiftRow_GF24(unsigned short &state);
void MixColumn_ShiftRow_GF28(unsigned short &state);
void iMixColumn_ShiftRow_GF28(unsigned short &state);
// Other 
void IT_CBC(unsigned short &ct,unsigned short* key);
void FT_CBC(unsigned short &ct,unsigned short* key, unsigned short nc);
void IT(unsigned short &ct,unsigned short* key);
void FT(unsigned short &ct,unsigned short* key, unsigned short nc);
void IT_Lat(unsigned short &ct,unsigned short* key);
void FT_Lat(unsigned short &ct,unsigned short* key, unsigned short nc);
void Lat(unsigned short &ct);
void iLat(unsigned short &ct);
void HeysLin(unsigned short &state);

// Key schedule
void key_exp(unsigned short* key,unsigned short nc,unsigned short mkey);

//  Differential table
void DifferentialTable();
unsigned int dif(unsigned short nc);

// Multiply in field GF(2^8) and GF(2^4)
unsigned char fld_mul_8(unsigned char a,unsigned char b);
unsigned char fld_mul_4(unsigned char a,unsigned char b);

// Print-parameters function
void print_parametrs(FILE* out);

// Test encryption and decryption
void test_cipher();

// Choice functions
void choice_cicles();
void choice_linpart();
void choice_functions();
void choice_sbox();
void choice_number_keys();

#endif /* CRYPTO_H_ */