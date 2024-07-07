
rule Ransom_Win32_Lyposit_A{
	meta:
		description = "Ransom:Win32/Lyposit.A,SIGNATURE_TYPE_PEHSTR_EXT,16 00 15 00 05 00 00 "
		
	strings :
		$a_01_0 = {89 7d f8 8d 43 02 66 3b 4d fc 73 0e 2b f8 8a 08 80 f1 cc 88 0c 07 40 4e 75 f4 } //10
		$a_01_1 = {0f b6 0e 83 c6 04 8a 16 c1 e0 08 03 c1 8b cb 84 d2 74 0c 2b f3 88 11 41 8a 14 0e } //10
		$a_01_2 = {69 c9 69 90 00 00 c1 e8 10 03 c1 8b 4a 04 56 0f b7 f1 69 f6 50 46 00 00 89 42 08 c1 e9 10 03 ce c1 e0 10 89 4a 04 } //2
		$a_01_3 = {fe 5f bc 07 fa 5f 04 b8 07 a1 e5 00 } //1
		$a_01_4 = {fd ff b8 05 f6 ff 51 be 42 0c 51 be 42 0e 51 be 42 7b 46 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=21
 
}