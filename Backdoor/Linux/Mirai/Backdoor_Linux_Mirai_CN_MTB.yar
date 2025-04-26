
rule Backdoor_Linux_Mirai_CN_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.CN!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {80 71 91 e7 03 40 d7 e7 05 40 24 e0 03 40 c7 e7 80 71 91 e7 03 40 d7 e7 0c 40 24 e0 03 40 c7 e7 80 71 91 e7 03 40 d7 e7 0e 40 24 e0 03 40 c7 e7 80 71 91 e7 03 40 d7 e7 02 40 24 e0 03 40 c7 e7 01 30 83 e2 } //1
		$a_00_1 = {f7 03 00 2a a0 02 40 f9 96 02 80 52 f3 c3 02 91 78 19 00 94 c1 02 00 4b a0 02 40 f9 f4 0a c1 1a 94 de 01 1b 73 19 00 94 14 00 14 0b e0 03 13 aa e1 03 14 2a a3 0e 00 94 a0 02 40 f9 e1 03 13 aa 7f ca 34 38 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}