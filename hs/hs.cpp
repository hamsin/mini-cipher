#include "hs.h"

int main(int argc,char* argv[])
{
	setlocale(0,"Russian");

	//unsigned short in=0xF621,state=0x1FF4;
	//unsigned short* key=NULL,Table[65536];


	//key=new unsigned short[3+2];

	//key_exp(key,3,(__rdtsc()%0x10000);

	//for(int i=0;i<16;i++)
	//{
	//	Sbox[i]=SboxAESD4[i];
	//	iSbox[i]=iSboxAESD4[i];
	//}

	//encrypt=heys_encrypt_it_ft;
	//decrypt=heys_decrypt_it_ft;

	//Lpart=MixColumn_ShiftRow_GF24;
	//iLpart=iMixColumn_ShiftRow_GF24;

	//for(int i=0;i<65536;i++)
	//{
	//	Table[i]=0;
	//}

	//for(int i=0;i<65536;i++)
	//{
	//	state=i;
	//	encrypt(state,key,3);
	//	Table[state]++;
	//	decrypt(state,key,3);
	//	//Lpart(state);
	//	//iLpart(state);

	//	if(state!=i)
	//		printf("============i=%d==========\n",i);
	//	if(i%10000==0)
	//		printf("i=%d\n",i);
	//}

	//for(int i=0;i<65536;i++)
	//	if(Table[i]==0)
	//		printf("============i=%d============\n",i);

	//return 0;

	char answer[6];
	int answ=0;

	do
	{
		do
		{
			print_parametrs(stdout);

			printf("===================================\n");
			printf("1. Выбрать Sbox\n");
			printf("2. Выбрать IT и FT преобразования\n");
			printf("3. Выбрать линейное преобразования\n");
			printf("4. Выбрать колчество циклов\n");
			printf("5. Выбрать количество тестируемых ключей\n");
			printf("===================================\n");
			printf("6. Посчитать полный дифференциал\n");
			printf("7. Проверка работоспособности шифра\n");
			printf("===================================\n");
			printf("0. Выход\n");
			printf("Ваш выбор:");

			scanf_s("%s",&answer,2);

			fflush(stdin);

		}
		while(answer[0]<'0' || answer[0]>'7');

		answ=atoi(answer);		
		switch(answ)
		{
			case 1:
				{
					choice_sbox();
					break;
				}
			case 2:
				{
					choice_functions();
					break;
				}
			case 3:
				{
					choice_linpart();
					break;
				}
			case 4:
				{
					choice_cicles();
					break;
				}
			case 5:
				{
					choice_number_keys();
					break;
				}
			case 6:
				{
					DifferentialTable();

					break;
				}
			case 7:
				{
					test_cipher();
					break;
				}
			case 0:
				{
					return 0;
					break;
				}
		}
	}
	while(1==1);

	return 0;
}
