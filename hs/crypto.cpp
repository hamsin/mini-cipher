#include <stdlib.h>
#include <stdio.h>
#include <intrin.h>
#include <conio.h>

#include "crypto.h"
#include "data.h"

//-------------------------------------------------------------------------------
void MixColumn_Full_Text(unsigned short &state)
{
	unsigned char b1=(state&0xF000)>>12; 
	unsigned char b2=(state&0x0F00)>>8;  
	unsigned char b3=(state&0x00F0)>>4;  
	unsigned char b4=(state&0x000F);
	unsigned char g[]={2,3,1,1,
						 1,2,3,1,
						 1,1,2,3,
						 3,1,1,2};
	
	state =(fld_mul_4(b1,g[0])^fld_mul_4(b2,g[4])^fld_mul_4(b3,g[8])^fld_mul_4(b4,g[12]))<<12;
	state|=(fld_mul_4(b1,g[1])^fld_mul_4(b2,g[5])^fld_mul_4(b3,g[9])^fld_mul_4(b4,g[13]))<<8;
	state|=(fld_mul_4(b1,g[2])^fld_mul_4(b2,g[6])^fld_mul_4(b3,g[10])^fld_mul_4(b4,g[14]))<<4;
	state|=(fld_mul_4(b1,g[3])^fld_mul_4(b2,g[7])^fld_mul_4(b3,g[11])^fld_mul_4(b4,g[15]));
}
//-------------------------------------------------------------------------------
void iMixColumn_Full_Text(unsigned short &state)
{
	unsigned char b1=(state&0xF000)>>12; 
	unsigned char b2=(state&0x0F00)>>8;  
	unsigned char b3=(state&0x00F0)>>4;  
	unsigned char b4=(state&0x000F);
	unsigned char g[]={14,11,13,9,
						 9,14,11,13,
						 13,9,14,11,
						 11,13,9,14};

	state =(fld_mul_4(b1,g[0])^fld_mul_4(b2,g[4])^fld_mul_4(b3,g[8])^fld_mul_4(b4,g[12]))<<12;
	state|=(fld_mul_4(b1,g[1])^fld_mul_4(b2,g[5])^fld_mul_4(b3,g[9])^fld_mul_4(b4,g[13]))<<8;
	state|=(fld_mul_4(b1,g[2])^fld_mul_4(b2,g[6])^fld_mul_4(b3,g[10])^fld_mul_4(b4,g[14]))<<4;
	state|=(fld_mul_4(b1,g[3])^fld_mul_4(b2,g[7])^fld_mul_4(b3,g[11])^fld_mul_4(b4,g[15]));
}
//-------------------------------------------------------------------------------
void MixColumn_ShiftRow_GF24(unsigned short &state)
{
    unsigned char b1 = (state&0xF000)>>12;
    unsigned char b2 = (state&0x000F);
    unsigned char b3 = (state&0x00F0)>>4;
    unsigned char b4 = (state&0x0F00)>>8;

    unsigned char g[4]={1, 3,
                          3, 1};

    state  = ((fld_mul_4(b1,g[0]))^(fld_mul_4(b3,g[2])))<<12;
    state ^= ((fld_mul_4(b2,g[0]))^(fld_mul_4(b4,g[2])))<<8;
    state ^= ((fld_mul_4(b1,g[1]))^(fld_mul_4(b3,g[3])))<<4;
    state ^= ((fld_mul_4(b2,g[1]))^(fld_mul_4(b4,g[3])));
}
//-------------------------------------------------------------------------------
void iMixColumn_ShiftRow_GF24(unsigned short &state)
{
    unsigned char b1 = (state&0xF000)>>12;
    unsigned char b2 = (state&0x0F00)>>8;
    unsigned char b3 = (state&0x00F0)>>4;
    unsigned char b4 = (state&0x000F);

    unsigned char g[4]={0xD, 0x4,
                          0x4, 0xD};

    state  = ((fld_mul_4(b1,g[0]))^(fld_mul_4(b3,g[2])))<<12;
    state ^= ((fld_mul_4(b2,g[0]))^(fld_mul_4(b4,g[2])));
    state ^= ((fld_mul_4(b1,g[1]))^(fld_mul_4(b3,g[3])))<<4;
    state ^= ((fld_mul_4(b2,g[1]))^(fld_mul_4(b4,g[3])))<<8;
}
//-------------------------------------------------------------------------------
void MixColumn_ShiftRow_GF28(unsigned short &state)
{
    unsigned char b1=(state&0x00FF); 
    unsigned char b2=(state&0xFF00)>>8;

    unsigned char g[]={1,3,
                         3,1};

	// MixColumn c ShiftRow
    state =(fld_mul_8(b1,g[0])^fld_mul_8(b2,g[1]))<<8;
    state|=(fld_mul_8(b1,g[2])^fld_mul_8(b2,g[3]));

}
//-------------------------------------------------------------------------------
void iMixColumn_ShiftRow_GF28(unsigned short &state)
{
	// ShiftRow
    unsigned char b1=(state&0xFF00)>>8;
    unsigned char b2=(state&0x00FF);

    unsigned char g[]={0xCB,0x46,
						 0x46,0xCB};

	// MixColumn
    state =(fld_mul_8(b1,g[0])^fld_mul_8(b2,g[1]));
    state|=(fld_mul_8(b1,g[2])^fld_mul_8(b2,g[3]))<<8;
}
//-------------------------------------------------------------------------------
void heys_encrypt(unsigned short &ct,unsigned short* key,unsigned short nc)
{
	ct=key[0]^ct;

	for(unsigned short i=0;i<nc;i++)
	{
		//Sbox
		ct=(Sbox[(ct&0xF000)>>12]<<12)|(Sbox[(ct&0x0F00)>>8]<<8)|(Sbox[(ct&0x00F0)>>4]<<4)|(Sbox[ct&0x000F]);
		//Liner Part
		Lpart(ct);
		//Add key
		ct=key[i+1]^ct;
	}

	//Sbox
	ct=(Sbox[(ct&0xF000)>>12]<<12)|(Sbox[(ct&0x0F00)>>8]<<8)|(Sbox[(ct&0x00F0)>>4]<<4)|(Sbox[ct&0x000F]);

	ct=ct^key[nc+1];
}
//-------------------------------------------------------------------------------
void heys_decrypt(unsigned short &ct,unsigned short* key,unsigned short nc)
{
	ct=ct^key[nc+1];

	//iSbox
	ct=(iSbox[(ct&0xF000)>>12]<<12)|(iSbox[(ct&0x0F00)>>8]<<8)|(iSbox[(ct&0x00F0)>>4]<<4)|(iSbox[ct&0x000F]);

	for(unsigned short i=0;i<nc;i++)
	{
		//Add key
		ct=key[nc-i]^ct;
		//Liner Part
		iLpart(ct);
		//iSbox
		ct=(iSbox[(ct&0xF000)>>12]<<12)|(iSbox[(ct&0x0F00)>>8]<<8)|(iSbox[(ct&0x00F0)>>4]<<4)|(iSbox[ct&0x000F]);
	}

	ct=key[0]^ct;
}
//-------------------------------------------------------------------------------
void CMS_encrypt(unsigned short &ct,unsigned short* key,unsigned short nc)
{
	ct=(key[0]+ct)%0x10000;

	for(unsigned short i=0;i<nc;i++)
	{
		ct=(key[i+1]+ct)%0x10000;
		Lat(ct);
	}

	ct=(key[nc+1]+ct)%0x10000;
}
//-------------------------------------------------------------------------------
void CMS_decrypt(unsigned short &ct,unsigned short* key,unsigned short nc)
{
	unsigned short tmp=0;

	for(int i=0;i<(nc+2)/2;i++)
	{
		tmp=key[i];
		key[i]=key[nc+1-i];
		key[nc+1-i]=tmp;
	}

	ct=(ct-key[0])%0x10000;

	for(unsigned short i=0;i<nc;i++)
	{
		iLat(ct);
		ct=(ct-key[i+1])%0x10000;
	}

	ct=(ct-key[nc+1])%0x10000;

	for(int i=0;i<(nc+2)/2;i++)
	{
		tmp=key[i];
		key[i]=key[nc+1-i];
		key[nc+1-i]=tmp;
	}
}
//-------------------------------------------------------------------------------
void heys_encrypt_it(unsigned short &ct,unsigned short* key,unsigned short nc)
{
	IT(ct,key);

	for(unsigned short i=0;i<nc;i++)
	{
		//Sbox
		ct=(Sbox[(ct&0xF000)>>12]<<12)|(Sbox[(ct&0x0F00)>>8]<<8)|(Sbox[(ct&0x00F0)>>4]<<4)|(Sbox[ct&0x000F]);
		//Liner Part
		Lpart(ct);
		//Add key
		ct=key[i+1]^ct;
	}

	ct=key[nc+1]^ct;
}
//-------------------------------------------------------------------------------
void heys_decrypt_it(unsigned short &ct,unsigned short* key,unsigned short nc)
{
	unsigned short tmp=0;

	for(int i=0;i<(nc+2)/2;i++)
	{
		tmp=key[i];
		key[i]=key[nc+1-i];
		key[nc+1-i]=tmp;
	}

	ct=key[0]^ct;

	for(unsigned short i=0;i<nc;i++)
	{
		//Add key
		ct=key[i+1]^ct;
		//Liner Part
		iLpart(ct);
		//iSbox
		ct=(iSbox[(ct&0xF000)>>12]<<12)|(iSbox[(ct&0x0F00)>>8]<<8)|(iSbox[(ct&0x00F0)>>4]<<4)|(iSbox[ct&0x000F]);
	}

	FT(ct,key,nc);

	for(int i=0;i<(nc+2)/2;i++)
	{
		tmp=key[i];
		key[i]=key[nc+1-i];
		key[nc+1-i]=tmp;
	}
}
//-------------------------------------------------------------------------------
void heys_encrypt_it_ft(unsigned short &ct,unsigned short* key,unsigned short nc)
{
	IT(ct,key);

	for(unsigned short i=0;i<nc;i++)
	{
		//Sbox
		ct=(Sbox[(ct&0xF000)>>12]<<12)|(Sbox[(ct&0x0F00)>>8]<<8)|(Sbox[(ct&0x00F0)>>4]<<4)|(Sbox[ct&0x000F]);
		//Liner Part
		Lpart(ct);
		//Add key
		ct=key[i+1]^ct;
	}

	FT(ct,key,nc);
}
//-------------------------------------------------------------------------------
void heys_decrypt_it_ft(unsigned short &ct,unsigned short* key,unsigned short nc)
{
	unsigned short tmp=0;

	for(int i=0;i<(nc+2)/2;i++)
	{
		tmp=key[i];
		key[i]=key[nc+1-i];
		key[nc+1-i]=tmp;
	}

	IT(ct,key);

	for(unsigned short i=0;i<nc;i++)
	{
		//Add key
		ct=key[i+1]^ct;
		//Liner Part
		iLpart(ct);
		//iSbox
		ct=(iSbox[(ct&0xF000)>>12]<<12)|(iSbox[(ct&0x0F00)>>8]<<8)|(iSbox[(ct&0x00F0)>>4]<<4)|(iSbox[ct&0x000F]);
	}

	FT(ct,key,nc);

	for(int i=0;i<(nc+2)/2;i++)
	{
		tmp=key[i];
		key[i]=key[nc+1-i];
		key[nc+1-i]=tmp;
	}
}
//-------------------------------------------------------------------------------
void heys_encrypt_lat_it(unsigned short &ct,unsigned short* key,unsigned short nc)
{
	IT_Lat(ct,key);

	for(unsigned short i=0;i<nc;i++)
	{
		//Sbox
		ct=(Sbox[(ct&0xF000)>>12]<<12)|(Sbox[(ct&0x0F00)>>8]<<8)|(Sbox[(ct&0x00F0)>>4]<<4)|(Sbox[ct&0x000F]);
		//Liner Part
		Lpart(ct);
		//Add key
		ct=key[i+1]^ct;
	}

	ct=key[nc+1]^ct;
}
//-------------------------------------------------------------------------------
void heys_decrypt_lat_it(unsigned short &ct,unsigned short* key,unsigned short nc)
{
	unsigned short tmp=0;

	for(int i=0;i<(nc+2)/2;i++)
	{
		tmp=key[i];
		key[i]=key[nc+1-i];
		key[nc+1-i]=tmp;
	}

	ct=key[0]^ct;

	for(unsigned short i=0;i<nc;i++)
	{
		//Add key
		ct=key[i+1]^ct;
		//Liner Part
		iLpart(ct);
		//iSbox
		ct=(iSbox[(ct&0xF000)>>12]<<12)|(iSbox[(ct&0x0F00)>>8]<<8)|(iSbox[(ct&0x00F0)>>4]<<4)|(iSbox[ct&0x000F]);
	}

	FT_Lat(ct,key,nc);

	for(int i=0;i<(nc+2)/2;i++)
	{
		tmp=key[i];
		key[i]=key[nc+1-i];
		key[nc+1-i]=tmp;
	}
}
//-------------------------------------------------------------------------------
void heys_encrypt_lat_ft(unsigned short &ct,unsigned short* key,unsigned short nc)
{
	ct=key[0]^ct;

	for(unsigned short i=0;i<nc;i++)
	{
		//Sbox
		ct=(Sbox[(ct&0xF000)>>12]<<12)|(Sbox[(ct&0x0F00)>>8]<<8)|(Sbox[(ct&0x00F0)>>4]<<4)|(Sbox[ct&0x000F]);
		//Liner Part
		Lpart(ct);
		//Add key
		ct=key[i+1]^ct;
	}

	FT_Lat(ct,key,nc);
}
//-------------------------------------------------------------------------------
void heys_decrypt_lat_ft(unsigned short &ct,unsigned short* key,unsigned short nc)
{
	unsigned short tmp=0;

	for(int i=0;i<(nc+2)/2;i++)
	{
		tmp=key[i];
		key[i]=key[nc+1-i];
		key[nc+1-i]=tmp;
	}

	IT_Lat(ct,key);

	for(unsigned short i=0;i<nc;i++)
	{
		//Add key
		ct=key[i+1]^ct;
		//Liner Part
		iLpart(ct);
		//iSbox
		ct=(iSbox[(ct&0xF000)>>12]<<12)|(iSbox[(ct&0x0F00)>>8]<<8)|(iSbox[(ct&0x00F0)>>4]<<4)|(iSbox[ct&0x000F]);
	}

	ct=key[nc+1]^ct;

	for(int i=0;i<(nc+2)/2;i++)
	{
		tmp=key[i];
		key[i]=key[nc+1-i];
		key[nc+1-i]=tmp;
	}
}
//-------------------------------------------------------------------------------
void heys_encrypt_lat_it_ft(unsigned short &ct,unsigned short* key,unsigned short nc)
{
	IT_Lat(ct,key);

	for(unsigned short i=0;i<nc;i++)
	{
		//Sbox
		ct=(Sbox[(ct&0xF000)>>12]<<12)|(Sbox[(ct&0x0F00)>>8]<<8)|(Sbox[(ct&0x00F0)>>4]<<4)|(Sbox[ct&0x000F]);
		//Liner Part
		Lpart(ct);
		//Add key
		ct=key[i+1]^ct;
	}

	FT_Lat(ct,key,nc);
}
//-------------------------------------------------------------------------------
void heys_decrypt_lat_it_ft(unsigned short &ct,unsigned short* key,unsigned short nc)
{
	unsigned short tmp=0;

	for(int i=0;i<(nc+2)/2;i++)
	{
		tmp=key[i];
		key[i]=key[nc+1-i];
		key[nc+1-i]=tmp;
	}

	IT_Lat(ct,key);

	for(unsigned short i=0;i<nc;i++)
	{
		//Add key
		ct=key[i+1]^ct;
		//Liner Part
		iLpart(ct);
		//iSbox
		ct=(iSbox[(ct&0xF000)>>12]<<12)|(iSbox[(ct&0x0F00)>>8]<<8)|(iSbox[(ct&0x00F0)>>4]<<4)|(iSbox[ct&0x000F]);
	}

	FT_Lat(ct,key,nc);

	for(int i=0;i<(nc+2)/2;i++)
	{
		tmp=key[i];
		key[i]=key[nc+1-i];
		key[nc+1-i]=tmp;
	}
}
//-------------------------------------------------------------------------------
void heys_encrypt_cbc(unsigned short &ct,unsigned short* key,unsigned short nc)
{
	IT_CBC(ct,key);

	for(unsigned short i=0;i<nc;i++)
	{
		//Sbox
		ct=(Sbox[(ct&0xF000)>>12]<<12)|(Sbox[(ct&0x0F00)>>8]<<8)|(Sbox[(ct&0x00F0)>>4]<<4)|(Sbox[ct&0x000F]);
		//Liner Part
		Lpart(ct);
		//Add key
		ct=key[i+1]^ct;
	}

	FT_CBC(ct,key,nc);
}
//-------------------------------------------------------------------------------
void heys_decrypt_cbc(unsigned short &ct,unsigned short* key,unsigned short nc)
{
	unsigned short tmp=0;

	for(int i=0;i<(nc+2)/2;i++)
	{
		tmp=key[i];
		key[i]=key[nc+1-i];
		key[nc+1-i]=tmp;
	}

	IT_CBC(ct,key);

	for(unsigned short i=0;i<nc;i++)
	{
		//Add key
		ct=key[i+1]^ct;
		//Liner Part
		iLpart(ct);
		//iSbox
		ct=(iSbox[(ct&0xF000)>>12]<<12)|(iSbox[(ct&0x0F00)>>8]<<8)|(iSbox[(ct&0x00F0)>>4]<<4)|(iSbox[ct&0x000F]);
	}

	FT_CBC(ct,key,nc);

	for(int i=0;i<(nc+2)/2;i++)
	{
		tmp=key[i];
		key[i]=key[nc+1-i];
		key[nc+1-i]=tmp;
	}
}
//-------------------------------------------------------------------------------
void heys_encrypt_cbc_it(unsigned short &ct,unsigned short* key,unsigned short nc)
{
	IT_CBC(ct,key);

	for(unsigned short i=0;i<nc;i++)
	{
		//Sbox
		ct=(Sbox[(ct&0xF000)>>12]<<12)|(Sbox[(ct&0x0F00)>>8]<<8)|(Sbox[(ct&0x00F0)>>4]<<4)|(Sbox[ct&0x000F]);
		//Liner Part
		Lpart(ct);
		//Add key
		ct=key[i+1]^ct;
	}

	//FT_CBC(ct,key,nc);
}
//-------------------------------------------------------------------------------
void heys_decrypt_cbc_it(unsigned short &ct,unsigned short* key,unsigned short nc)
{
	unsigned short tmp=0;

	for(int i=0;i<(nc+2)/2;i++)
	{
		tmp=key[i];
		key[i]=key[nc+1-i];
		key[nc+1-i]=tmp;
	}

	//IT_CBC(ct,key,nc);

	for(unsigned short i=0;i<nc;i++)
	{
		//Add key
		ct=key[i+1]^ct;
		//Liner Part
		iLpart(ct);
		//iSbox
		ct=(iSbox[(ct&0xF000)>>12]<<12)|(iSbox[(ct&0x0F00)>>8]<<8)|(iSbox[(ct&0x00F0)>>4]<<4)|(iSbox[ct&0x000F]);
	}

	FT_CBC(ct,key,nc);

	for(int i=0;i<(nc+2)/2;i++)
	{
		tmp=key[i];
		key[i]=key[nc+1-i];
		key[nc+1-i]=tmp;
	}
}
//-------------------------------------------------------------------------------
void heys_encrypt_cbc_ft(unsigned short &ct,unsigned short* key,unsigned short nc)
{
	//IT_CBC(ct,key,nc);

	for(unsigned short i=0;i<nc;i++)
	{
		//Sbox
		ct=(Sbox[(ct&0xF000)>>12]<<12)|(Sbox[(ct&0x0F00)>>8]<<8)|(Sbox[(ct&0x00F0)>>4]<<4)|(Sbox[ct&0x000F]);
		//Liner Part
		Lpart(ct);
		//Add key
		ct=key[i+1]^ct;
	}

	FT_CBC(ct,key,nc);
}
//-------------------------------------------------------------------------------
void heys_decrypt_cbc_ft(unsigned short &ct,unsigned short* key,unsigned short nc)
{
	unsigned short tmp=0;

	for(int i=0;i<(nc+2)/2;i++)
	{
		tmp=key[i];
		key[i]=key[nc+1-i];
		key[nc+1-i]=tmp;
	}

	IT_CBC(ct,key);

	for(unsigned short i=0;i<nc;i++)
	{
		//Add key
		ct=key[i+1]^ct;
		//Liner Part
		iLpart(ct);
		//iSbox
		ct=(iSbox[(ct&0xF000)>>12]<<12)|(iSbox[(ct&0x0F00)>>8]<<8)|(iSbox[(ct&0x00F0)>>4]<<4)|(iSbox[ct&0x000F]);
	}

	//FT_CBC(ct,key,nc);

	for(int i=0;i<(nc+2)/2;i++)
	{
		tmp=key[i];
		key[i]=key[nc+1-i];
		key[nc+1-i]=tmp;
	}
}
//-------------------------------------------------------------------------------
unsigned int dif(unsigned short nc)
{
	long double average=0;
	unsigned short *key=NULL, c_text=0, Sbox_Table[65536];
	FILE *fout=NULL;
	unsigned int Dif_Table[65536], max=0;

	key=new unsigned short[nc+2];

	for(int k=0;k<NumberKey;k++)
	{
		if(NumberKey==65536)
			key_exp(key,nc,(unsigned short)k);
		else
			key_exp(key,nc,(__rdtsc()*(k+1))%0x10000);

		for(int i=0;i<65536;i++)
		{
			c_text=(unsigned short)i;
			encrypt(c_text,key,nc);
			Sbox_Table[i]=c_text;
			Dif_Table[i]=0;
		}

		max=0;

		for(int j=0;j<65536;j++)
		{
			for(int i=0;i<65536;i++)
			{
				Dif_Table[Sbox_Table[i]^Sbox_Table[j^i]]++; // ??? ошибка ???
			}

			if( j == 0 )
			{
				Dif_Table[0]=0;
				continue;
			}

			if(k==0)
			{
				for(int i=0;i<65536;i++)
				{
					FullDifTable[Dif_Table[i]]++;
				}
			}
	
			for(int i=0;i<65536;i++)
			{
				if(max<Dif_Table[i])
					max=Dif_Table[i];
				Dif_Table[i]=0;
			}
		}
		printf("max=%d\n",max);
		average=average+((long double)max/(long double)NumberKey);
	}

	fopen_s(&fout,"result.txt","a+");

	if(!fout)
		perror("Can't open file \"result.txt\"\n");

	fprintf(fout,"=======================================\n");
	fprintf(fout,"Циклов || Среднее max значение диф. табл.\n");
	fprintf(fout,"%.5d  ||             %.2f\n",nc,average);
	fprintf(fout,"=======================================\n");
	fprintf(fout,"Значение диф. табл. ||  количество\n");
	for(int i=0;i<32768;i++)
	{
		if(FullDifTable[i]!=0)
		{
			fprintf(fout,"      %.5d         ||  %.10I64d\n",i,FullDifTable[i]);
			FullDifTable[i]=0;
		}
	}

	fclose(fout);

	printf("Среднее значение диф. хар-ки для %d циклов = %.2f\n",nc,average);

	delete []key;

	return max;
}
//-------------------------------------------------------------------------------
void IT_Lat(unsigned short &ct,unsigned short* key)
{
	ct=(ct+key[0])%0x10000;

	ct=(ct&0x0FFF)^(LSbox[0][(ct&0xF000)>>12]<<12);
	ct=(ct&0xF0FF)^(LSbox[(ct&0xF000)>>12][(ct&0x0F00)>>8]<<8);
	ct=(ct&0xFF0F)^(LSbox[(ct&0x0F00)>>8][(ct&0x00F0)>>4]<<4);
	ct=(ct&0xFFF0)^(LSbox[(ct&0x00F0)>>4][(ct&0x000F)]);

	ct=(ct&0xFFF0)^(LSbox[0][(ct&0x000F)]);
	ct=(ct&0xFF0F)^(LSbox[(ct&0x000F)][(ct&0x00F0)>>4]<<4);
	ct=(ct&0xF0FF)^(LSbox[(ct&0x00F0)>>4][(ct&0x0F00)>>8]<<8);
	ct=(ct&0x0FFF)^(LSbox[(ct&0x0F00)>>8][(ct&0xF000)>>12]<<12);
	
}
//-------------------------------------------------------------------------------
void FT_Lat(unsigned short &ct,unsigned short* key, unsigned short nc)
{
	ct=(ct&0x0FFF)^(iLSbox[(ct&0x0F00)>>8][(ct&0xF000)>>12]<<12);
	ct=(ct&0xF0FF)^(iLSbox[(ct&0x00F0)>>4][(ct&0x0F00)>>8]<<8);
	ct=(ct&0xFF0F)^(iLSbox[(ct&0x000F)][(ct&0x00F0)>>4]<<4);
	ct=(ct&0xFFF0)^(iLSbox[0][(ct&0x000F)]);

	ct=(ct&0xFFF0)^(iLSbox[(ct&0x00F0)>>4][ct&0x000F]);
	ct=(ct&0xFF0F)^(iLSbox[(ct&0x0F00)>>8][(ct&0x00F0)>>4]<<4);
	ct=(ct&0xF0FF)^(iLSbox[(ct&0xF000)>>12][(ct&0x0F00)>>8]<<8);
	ct=(ct&0x0FFF)^(iLSbox[0][(ct&0xF000)>>12]<<12);

	ct=(ct-key[nc+1])%0x10000;
}
//-------------------------------------------------------------------------------
void IT_CBC(unsigned short &ct,unsigned short* key)
{
	ct=(ct+key[0])%0x10000;

	ct=(ct&0x0FFF)|(Sbox[(ct&0xF000)>>12]<<12);
	ct=(ct&0xF0FF)|(Sbox[((ct&0x0F00)>>8)^((ct&0xF000)>>12)]<<8);
	ct=(ct&0xFF0F)|(Sbox[((ct&0x00F0)>>4)^((ct&0x0F00)>>8)]<<4);
	ct=(ct&0xFFF0)|(Sbox[(ct&0x000F)^((ct&0x00F0)>>4)]);

	ct=(ct&0xFFF0)|(Sbox[ct&0x000F]);
	ct=(ct&0xFF0F)|(Sbox[((ct&0x00F0)>>4)^(ct&0x000F)]<<4);
	ct=(ct&0xF0FF)|(Sbox[((ct&0x0F00)>>8)^((ct&0x00F0)>>4)]<<8);
	ct=(ct&0x0FFF)|(Sbox[((ct&0xF000)>>12)^((ct&0x0F00)>>8)]<<12);
}
//-------------------------------------------------------------------------------
void FT_CBC(unsigned short &ct,unsigned short* key, unsigned short nc)
{
	ct=(ct&0x0FFF)|((iSbox[((ct&0xF000)>>12)]^((ct&0x0F00)>>8))<<12);
	ct=(ct&0xF0FF)|((iSbox[((ct&0x0F00)>>8)]^((ct&0x00F0)>>4))<<8);
	ct=(ct&0xFF0F)|((iSbox[((ct&0x00F0)>>4)]^(ct&0x000F))<<4);
	ct=(ct&0xFFF0)|(iSbox[(ct&0x000F)]);

	ct=(ct&0xFFF0)|(iSbox[ct&0x000F]^((ct&0x00F0)>>4));
	ct=(ct&0xFF0F)|((iSbox[((ct&0x00F0)>>4)]^((ct&0x0F00)>>8))<<4);
	ct=(ct&0xF0FF)|((iSbox[((ct&0x0F00)>>8)]^((ct&0xF000)>>12))<<8);
	ct=(ct&0x0FFF)|(iSbox[(ct&0xF000)>>12]<<12);

	ct=(ct-key[nc+1])%0x10000;
}
//-------------------------------------------------------------------------------
void IT(unsigned short &ct,unsigned short* key)
{
	unsigned short tmp=0;

	//Add key
	ct=(
		(
		((ct&0xFF)+(key[0]&0xFF))&0xFF
		) | 
		(
		 (
		 ((ct&0xFF00)>>8)+((key[0]&0xFF00)>>8)
		 )&0xFF
		 )<<8
		 );

	//Sbox
	ct=(Sbox[(ct&0xF000)>>12]<<12)|(Sbox[(ct&0x0F00)>>8]<<8)|(Sbox[(ct&0x00F0)>>4]<<4)|(Sbox[ct&0x000F]);

	//Shift
	ct=((ct&0xF000)>>4)|((ct&0x0F00)<<4)|((ct&0x00F0)>>4)|((ct&0x000F)<<4);

	//Imix
	tmp=((ct&0xFF00)>>8)^(ct&0x00FF);
	tmp=((tmp&0xC0)>>6)^((tmp&0x003F)<<2);

	ct=((ct&0xFF00)^(tmp<<8))^((ct&0x00FF)^tmp);

}
//-------------------------------------------------------------------------------
void FT(unsigned short &ct,unsigned short* key, unsigned short nc)
{
	unsigned short tmp=0;

	//iImix
	tmp=((ct&0xFF00)>>8)^(ct&0x00FF);
	tmp=((tmp&0xC0)>>6)^((tmp&0x003F)<<2);

	ct=((ct&0xFF00)^(tmp<<8))^((ct&0x00FF)^tmp);

	//Shift
	ct=((ct&0xF000)>>4)|((ct&0x0F00)<<4)|((ct&0x00F0)>>4)|((ct&0x000F)<<4);

	//iSbox
	ct=(iSbox[(ct&0xF000)>>12]<<12)|(iSbox[(ct&0x0F00)>>8]<<8)|(iSbox[(ct&0x00F0)>>4]<<4)|(iSbox[ct&0x000F]);

	//Sub key

	ct=(
		(
		((ct&0xFF)-(key[nc+1]&0xFF))&0xFF
		) | 
		(
		 (
		 ((ct&0xFF00)>>8)-((key[nc+1]&0xFF00)>>8)
		 )&0xFF
		 )<<8
		 );
}
//-------------------------------------------------------------------------------
void Lat(unsigned short &ct)
{
	ct=(ct&0x0FFF)^(Sbox[(  C1               + ((ct&0xF000)>>12) ) %16]<<12);
	ct=(ct&0xF0FF)^(Sbox[( ((ct&0xF000)>>12) + ((ct&0x0F00)>>8)  ) %16]<<8);
	ct=(ct&0xFF0F)^(Sbox[( ((ct&0x0F00)>>8)  + ((ct&0x00F0)>>4)  ) %16]<<4);
	ct=(ct&0xFFF0)^(Sbox[( ((ct&0x00F0)>>4)  + (ct&0x000F)       ) %16]);

	ct=(ct&0xFFF0)^(Sbox[(  C2              + (ct&0x000F)       ) %16]);
	ct=(ct&0xFF0F)^(Sbox[( (ct&0x000F)      + ((ct&0x00F0)>>4)  ) %16]<<4);
	ct=(ct&0xF0FF)^(Sbox[( ((ct&0x00F0)>>4) + ((ct&0x0F00)>>8)  ) %16]<<8);
	ct=(ct&0x0FFF)^(Sbox[( ((ct&0x0F00)>>8) + ((ct&0xF000)>>12) ) %16]<<12);
}
//-------------------------------------------------------------------------------
void iLat(unsigned short &ct)
{
	ct=(ct&0x0FFF)^(( ( ( iSbox[(ct&0xF000)>>12] - ((ct&0x0F00)>>8)   ) %16) &0x0F) <<12);
	ct=(ct&0xF0FF)^(( ( ( iSbox[(ct&0x0F00)>>8]  - ((ct&0x00F0)>>4)   ) %16) &0x0F) <<8);
	ct=(ct&0xFF0F)^(( ( ( iSbox[(ct&0x00F0)>>4]  - (ct&0x000F)        ) %16) &0x0F) <<4);
	ct=(ct&0xFFF0)^(( ( ( iSbox[(ct&0x000F)]     - C2                 ) %16) &0x0F)   );

	ct=(ct&0xFFF0)^(( ( ( iSbox[ct&0x000F]       - ((ct&0x00F0)>>4)   ) %16 ) &0x0F)  );
	ct=(ct&0xFF0F)^(( ( ( iSbox[(ct&0x00F0)>>4]  - ((ct&0x0F00)>>8)   ) %16 ) &0x0F) <<4);
	ct=(ct&0xF0FF)^(( ( ( iSbox[(ct&0x0F00)>>8]  - ((ct&0xF000)>>12)  ) %16 ) &0x0F) <<8);
	ct=(ct&0x0FFF)^(( ( ( iSbox[(ct&0xF000)>>12] - C1                 ) %16 ) &0x0F) <<12);
}

//-------------------------------------------------------------------------------
void HeysLin(unsigned short &state)
{
	state=((((state&0x8000)>>12)|((state&0x0800)>>9)|((state&0x0080)>>6)|((state&0x0008)>>3))<<12)|
   ((((state&0x4000)>>11)|((state&0x0400)>>8)|((state&0x0040)>>5)|((state&0x0004)>>2))<<8)|
   ((((state&0x2000)>>10)|((state&0x0200)>>7)|((state&0x0020)>>4)|((state&0x0002)>>1))<<4)|
   (((state&0x1000)>>9)|((state&0x0100)>>6)|((state&0x0010)>>3)|((state&0x0001)));
}
//-------------------------------------------------------------------------------
void DifferentialTable()
{
	FILE *fout=NULL;

	fopen_s(&fout,"result.txt","a+");

	if(!fout)
		perror("Can't open file \"result.txt\"\n");

	print_parametrs(fout);

	fclose(fout);

	for(unsigned short i=n_cicles_b;i<n_cicles_e+1;i++)
	{
		dif(i);
	}
	_getch();
}
void key_exp(unsigned short* key,unsigned short nc,unsigned short mkey)
{
	key[0]=mkey;

	unsigned char* r=new unsigned char[nc+1];

	unsigned short temp=0;

	for(int i=0;i<nc+1;i++)
	{
		temp=0x10;
		for(int j=0;j<i;j++)
		{
			temp=temp<<1;
			if(temp>0xFF)
			{
				temp^=0x130;
			}
		}
		r[i]=temp&0x00FF;
	}

	for(int i=1;i<nc+2;i++)
	{
		key[i]=((Sbox[(key[i-1]&0x00F0)>>4])|(Sbox[key[i-1]&0x000F]<<4))^((key[i-1]&0xFF00)>>8)^(r[i-1]);
		key[i]=(key[i]^(key[i-1]&0x00FF))^(key[i]<<8);
	}

	delete []r;
}
//-------------------------------------------------------------------------------
void test_cipher()
{
	unsigned short* key=NULL, c_text=0x1234;

	if(memcmp(Sbox,iSbox,16)==0)
	{
		printf("Выберите Sbox\nДля продолжения нажмите любую клавишу . . .\n");
		_getch();
		return;
	}
	if(encrypt==NULL || decrypt==NULL)
	{
		printf("Выберите алгоритм преобразования\nДля продолжения нажмите любую клавишу . . .\n");
		_getch();
		return;
	}

	key=new unsigned short[n_cicles_e+2];

	key_exp(key,n_cicles_e,__rdtsc()%0x10000);

	encrypt(c_text,key,n_cicles_e);
	decrypt(c_text,key,n_cicles_e);

	printf("Encrypt/Decrypt = %s\n",c_text==0x1234 ? "true":"false");

	printf("Для продолжения нажмите любую клавишу . . .\n");
	_getch();

	delete []key;
}
//-------------------------------------------------------------------------------
void print_parametrs(FILE* out)
{
	if(out==stdout)
		for(int i=0;i<25;i++)
			fprintf(out,"\n");

	fprintf(out,"Текущий выбранный Sbox={");
	for(int i=0;i<16;i++)
	{
		if(i!=15)
			fprintf(out,"%X,",Sbox[i]);
		else
			fprintf(out,"%X",Sbox[i]);
	}
	fprintf(out,"}\n");
	fprintf(out,"Текущий выбранные IT и FT преобразования: ");


	if(encrypt==heys_encrypt)
	{
		fprintf(out,"Алгоритм Хейса\n");
	}
	else
	{
		if(encrypt==heys_encrypt_it)
		{
			fprintf(out,"Алгоритм Хейса с начальным IT преобразованием\n");
		}
		else
		{
			if(encrypt==heys_encrypt_it_ft)
			{
				fprintf(out,"Алгоритм Хейса с начальным IT и FT преобразованием\n");
			}
			else
			{
				if(encrypt==heys_encrypt_lat_it)
				{
					fprintf(out,"Алгоритм Хейса с IT ШУП\n");	
				}
				else
				{
					if(encrypt==heys_encrypt_lat_it)
					{
						fprintf(out,"Алгоритм Хейса с IT ШУП\n");	
					}
					else
					{
						if(encrypt==heys_encrypt_lat_ft)
						{
							fprintf(out,"Алгоритм Хейса с FT ШУП\n");
						}
						else
						{
							if(encrypt==heys_encrypt_lat_it_ft)
							{
								fprintf(out,"Алгоритм Хейса с IT и FT ШУП\n");
							}
							else
							{
								if(encrypt==heys_encrypt_cbc)
								{
									fprintf(out,"Алгоритм Хейса с IT и FT CBC\n");
								}
								else
								{
									if(encrypt==heys_encrypt_cbc_it)
									{
										fprintf(out,"Алгоритм Хейса с IT CBC\n");
									}
									else
									{
										if(encrypt==heys_encrypt_cbc_ft)
										{
											fprintf(out,"Алгоритм Хейса с FT CBC\n");
										}
										else
										{
											if(encrypt==CMS_encrypt)
											{
												fprintf(out,"Алгоритм ШУП\n");	
											}
											else
											{
												fprintf(out,"Не выбраны\n");
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	fprintf(out,"Текущий выбранная линейная часть: ");
	if(Lpart==HeysLin)
	{
		fprintf(out,"Линейная часть по алгоритму Хейса\n");
	}
	else
	{
		if(Lpart==MixColumn_ShiftRow_GF24)
		{
			fprintf(out,"Линейная часть MixColumn и ShiftRow GF(2^4)\n");
		}
		else
		{
			if(Lpart==MixColumn_ShiftRow_GF28)
			{
				fprintf(out,"Линейная часть MixColumn и ShiftRow GF(2^8)\n");
			}
			else
			{
				if(Lpart==MixColumn_Full_Text)
				{
					fprintf(out,"Линейная часть MixColumn на весь текст\n");
				}
				else
				{
					fprintf(out,"Не выбрана\n");
				}
			}
		}
	}
	fprintf(out,"Текущее количество циклов: от %d до %d\n",n_cicles_b,n_cicles_e);
	fprintf(out,"Количество тестируемых ключей: %d\n",NumberKey);
}
//-------------------------------------------------------------------------------
unsigned char fld_mul_8(unsigned char a,unsigned char b)
{
    unsigned short ret=0;
    int i=0;

    for(i=0;i<8;i++)
    {
            if((b&(1<<i))==(1<<i))
                    ret^=(a<<i);
    }

    for(i=14;i>=8;i--)
    {
            if((ret&(1<<i))==(1<<i))
                    ret^=(f_x_8<<(i-8));
    }

    return (unsigned char)ret;
}
//-------------------------------------------------------------------------------
unsigned char fld_mul_4(unsigned char a,unsigned char b)
{
    unsigned char ret=0;
    int i=0;

	a&=0xF;
	b&=0xF;

    for(i=0;i<4;i++)
    {
            if((b&(1<<i))==(1<<i))
                    ret^=(a<<i);
    }

    for(i=6;i>=4;i--)
    {
            if((ret&(1<<i))==(1<<i))
                    ret^=(f_x_4<<(i-4));
    }

    return ret;
}
//-------------------------------------------------------------------------------
void choice_functions_2()
{
	char answer[2];

	do
	{
		do
		{
			print_parametrs(stdout);

			printf("Выберите алгоритм IT и FT преобразования:\n");
			printf("1. Алгоритм Хейса с IT ШУП\n");
			printf("2. Алгоритм Хейса с FT ШУП\n");
			printf("3. Алгоритм Хейса с IT CBC\n");
			printf("4. Алгоритм Хейса с FT CBC\n");
			printf("0. Выход\n");
			printf("Ваш выбор:");

			scanf_s("%s",&answer,2);
			fflush(stdin);
		}
		while(answer[0]<'0' || answer[0]>'4');

		int answ=atoi(answer);

		switch(answ)
		{
			case 1:
				{
					encrypt=heys_encrypt_lat_it;
					decrypt=heys_decrypt_lat_it;
					break;
				}
			case 2:
				{
					encrypt=heys_encrypt_lat_ft;
					decrypt=heys_decrypt_lat_ft;
					break;
				}
			case 3:
				{
					encrypt=heys_encrypt_cbc_it;
					decrypt=heys_decrypt_cbc_it;
					break;
				}
			case 4:
				{
					encrypt=heys_encrypt_cbc_ft;
					decrypt=heys_decrypt_cbc_ft;
					break;
				}
			case 0:
				{
					return;
					break;
				}
		}
	}
	while(1==1);
}
//-------------------------------------------------------------------------------
void choice_functions()
{
	char answer[2];

	do
	{
		do
		{
			print_parametrs(stdout);

			printf("Выберите алгоритм IT и FT преобразования:\n");
			printf("1. Алгоритм Хейса\n");
			printf("2. Алгоритм Хейса с начальным IT и FT преобразованием\n");
			printf("3. Алгоритм Хейса с IT и FT ШУП\n");
			printf("4. Алгоритм Хейса с IT и FT CBC\n");
			printf("5. Алгоритм ШУП\n");
			printf("6. Дополнительные алгоритмы\n");
			printf("0. Выход\n");
			printf("Ваш выбор:");

			scanf_s("%s",&answer,2);
			fflush(stdin);
		}
		while(answer[0]<'0' || answer[0]>'6');

		int answ=atoi(answer);

		switch(answ)
		{
			case 1:
				{
					encrypt=heys_encrypt;
					decrypt=heys_decrypt;
					break;
				}
			case 2:
				{
					encrypt=heys_encrypt_it_ft;
					decrypt=heys_decrypt_it_ft;
					break;
				}
			case 3:
				{
					encrypt=heys_encrypt_lat_it_ft;
					decrypt=heys_decrypt_lat_it_ft;
					break;
				}
			case 4:
				{
					encrypt=heys_encrypt_cbc;
					decrypt=heys_decrypt_cbc;
					break;
				}
			case 5:
				{
					encrypt=CMS_encrypt;
					decrypt=CMS_decrypt;					
					break;
				}
			case 6:
				{
					choice_functions_2();
					break;
				}
			case 0:
				{
					return;
				}
		}
	}
	while(1==1);
}
//-------------------------------------------------------------------------------
void choice_linpart()
{
	char answer[2];

	do
	{
		do
		{
			print_parametrs(stdout);

			printf("Выберите алгоритм линейной части:\n");
			printf("1. Линейная часть по алгоритму Хейса\n");
			printf("2. Линейная часть MixColumn и ShiftRow GF(2^4)\n");
			printf("3. Линейная часть MixColumn и ShiftRow GF(2^8)\n");
			printf("4. Линейная часть MixColumn на весь текст\n");
			printf("0. Выход\n");
			printf("Ваш выбор:");

			scanf_s("%s",&answer,2);
			fflush(stdin);
		}
		while(answer[0]<'0' || answer[0]>'4');

		int answ=atoi(answer);

		switch(answ)
		{
			case 1:
				{
					Lpart=HeysLin;
					iLpart=HeysLin;
					break;
				}
			case 2:
				{
					Lpart=MixColumn_ShiftRow_GF24;
					iLpart=iMixColumn_ShiftRow_GF24;
					break;
				}
			case 3:
				{
					Lpart=MixColumn_ShiftRow_GF28;
					iLpart=iMixColumn_ShiftRow_GF28;
					break;
				}
			case 4:
				{
					Lpart=MixColumn_Full_Text;
					iLpart=iMixColumn_Full_Text;
					break;
				}
			case 0:
				{
					return;
					break;
				}
		}
	}
	while(1==1);
}
//-------------------------------------------------------------------------------
void choice_cicles()
{
	char answer[6];

	int answ=0;

	do
	{
		do
		{
			print_parametrs(stdout);

			printf("1. Ввести минимальное количество циклов\n");
			printf("2. Ввести максимальное количество циклов\n");
			printf("0. Выход\n");
			printf("Ваш выбор:");

			scanf_s("%s",&answer,2);
			fflush(stdin);
		}
		while(answer[0]<'0' || answer[0]>'2');

		answ=atoi(answer);

		switch(answ)
		{
			case 1:
				{
					int answ_cicles=0;
					do
					{
						printf("Введите количество циклов:");
						scanf_s("%s",&answer,6);
						fflush(stdin);

						answ_cicles=atoi(answer);

						if(answ_cicles<1 || answ_cicles>65535)
						{
							printf("Введите число от 1 до 65535\n");
							continue;
						}
						else
						{
							break;
						}
					}
					while(1==1);

					n_cicles_b=(unsigned short)answ_cicles;

					break;
				}
			case 2:
				{
					int answ_cicles=0;
					do
					{
						printf("Введите количество циклов:");
						scanf_s("%s",&answer,6);
						fflush(stdin);

						answ_cicles=atoi(answer);

						if(answ_cicles<1 || answ_cicles>65535)
						{
							printf("Введите число от 1 до 65535\n");
							continue;
						}
						else
						{
							break;
						}
					}
					while(1==1);

					n_cicles_e=(unsigned short)answ_cicles;

					break;
				}
			case 0:
				{
					return;
					break;
				}
		}
	}
	while(1==1);

	return;
}
//-------------------------------------------------------------------------------
void choice_sbox()
{
	char answer[2];

	do
	{
		do
		{
			print_parametrs(stdout);

			printf("Выберите Sbox:\n");
			printf("1. {A,4,3,B,8,E,2,C,5,7,6,F,0,1,9,D} (SboxAES)\n");
			printf("2. {E,4,D,1,2,F,B,8,3,A,6,C,5,9,0,7} (SboxHEYS)\n");
			printf("3. {B,C,5,0,1,3,2,7,8,4,D,F,6,9,E,A} (SboxD8F2)\n");
			printf("4. {4,6,F,B,E,7,5,D,9,C,1,0,3,8,A,2} (SboxD6F0)\n");
			printf("5. {C,9,4,6,8,E,D,5,3,F,B,0,A,2,1,7} (SboxD8F0)\n");
			printf("6. {8,3,1,9,A,B,E,C,5,D,F,2,0,4,7,6} (SboxD12)\n");
			printf("7. Ввести Sbox\n");
			printf("0. Выход\n");
			printf("Ваш выбор:");

			scanf_s("%s",&answer,2);
			fflush(stdin);
		}
		while(answer[0]<'0' || answer[0]>'7');

		int answ=atoi(answer);

		switch(answ)
		{
			case 1:
				{
					for(int i=0;i<16;i++)
					{
						Sbox[i]=SboxAESD4[i];
						iSbox[i]=iSboxAESD4[i];
					}
					break;
				}
			case 2:
				{
					for(int i=0;i<16;i++)
					{
						Sbox[i]=SboxHEYSD8[i];
						iSbox[i]=iSboxHEYSD8[i];
					}
					break;
				}
			case 3:
				{
					for(int i=0;i<16;i++)
					{
						Sbox[i]=SboxD8F2[i];
						iSbox[i]=iSboxD8F2[i];
					}
					break;
				}
			case 4:
				{
					for(int i=0;i<16;i++)
					{
						Sbox[i]=SboxD6F0[i];
						iSbox[i]=iSboxD6F0[i];
					}
					break;
				}
			case 5:
				{
					for(int i=0;i<16;i++)
					{
						Sbox[i]=SboxD8F0[i];
						iSbox[i]=iSboxD8F0[i];
					}
					break;
				}
			case 6:
				{
					for(int i=0;i<16;i++)
					{
						Sbox[i]=SboxD12[i];
						iSbox[i]=iSboxD12[i];
					}
					break;
				}
			case 7:
				{
					printf("Введите Sbox:\n");
					for(int i=0;i<16;i++)
					{
						printf("Sbox[%i]=",i);
						scanf_s("%X",&Sbox[i],1);
						fflush(stdin);
					}
					for(unsigned short i=0;i<16;i++)
					{
						iSbox[Sbox[i]]=i;
					}
					break;
				}
			case 0:
				{
					return;
					break;
				}
		}
	}
	while(1==1);
}
//-------------------------------------------------------------------------------
void choice_number_keys()
{
	char answer[6];

	int answ=0;

	do
	{
		do
		{
			print_parametrs(stdout);

			printf("1. Ввести количество тестируемых ключей\n");
			printf("0. Выход\n");
			printf("Ваш выбор:");

			scanf_s("%s",&answer,2);
			fflush(stdin);
		}
		while(answer[0]<'0' || answer[0]>'1');

		answ=atoi(answer);

		switch(answ)
		{
			case 1:
				{
					int answ_nk=0;
					do
					{
						printf("Введите количество ключей:");
						scanf_s("%s",&answer,6);
						fflush(stdin);

						answ_nk=atoi(answer);

						if(answ_nk<1 || answ_nk>65535)
						{
							printf("Введите число от 1 до 65535\n");
							continue;
						}
						else
						{
							break;
						}
					}
					while(1==1);

					NumberKey=(unsigned short)answ_nk;

					break;
				}
			case 0:
				{
					return;
					break;
				}
		}
	}
	while(1==1);

	return;
}
//-------------------------------------------------------------------------------
