
rule Ransom_Win64_Hive_B{
	meta:
		description = "Ransom:Win64/Hive.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {b1 01 48 ba 09 2a 86 48 86 f7 0d 00 41 88 4d 18 41 89 55 19 48 89 d1 48 c1 e9 30 41 88 4d 1f 48 c1 ea 20 66 41 89 55 1d 49 89 75 20 49 89 6d 30 4d 89 4d 48 49 89 45 50 } //1
		$a_01_1 = {0f b7 c9 48 c1 e1 08 40 0f b6 fe 48 09 cf 48 c1 e3 20 0f b6 f2 48 c1 e6 18 48 09 de 48 09 fe } //1
		$a_01_2 = {77 69 6e 64 6f 77 73 5f 65 6e 63 72 79 70 74 } //1 windows_encrypt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}