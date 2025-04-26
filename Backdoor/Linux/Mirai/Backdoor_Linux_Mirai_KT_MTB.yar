
rule Backdoor_Linux_Mirai_KT_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.KT!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {f0 47 2d e9 01 70 a0 e1 00 40 a0 e1 18 d0 4d e2 00 10 a0 e3 60 20 a0 e3 07 00 a0 e1 a5 09 00 eb 01 c0 d4 e5 05 e0 d4 e5 00 00 d4 e5 04 10 d4 e5 02 90 d4 e5 06 a0 d4 e5 03 80 d4 e5 0c 04 80 e1 0e 14 81 e1 07 c0 d4 e5 09 08 80 e1 0a 18 81 e1 08 2c 80 e1 0c 3c 81 e1 0c 00 87 e8 59 10 d4 e5 5d 00 d4 e5 58 20 d4 e5 5c 30 d4 e5 5e e0 d4 e5 5a 80 d4 e5 } //1
		$a_01_1 = {0e 00 2d e9 10 40 2d e9 04 d0 4d e2 14 30 8d e2 00 30 8d e5 0c 10 8d e2 06 00 91 e8 36 00 90 ef 01 0a 70 e3 00 40 a0 e1 03 00 00 9a 5e 02 00 eb 00 30 64 e2 00 30 80 e5 00 40 e0 e3 04 00 a0 e1 04 d0 8d e2 10 40 bd e8 0c d0 8d e2 0e f0 a0 e1 } //1
		$a_01_2 = {10 40 2d e9 02 00 90 ef 01 0a 70 e3 00 40 a0 e1 03 00 00 9a 85 02 00 eb 00 30 64 e2 00 30 80 e5 00 40 e0 e3 04 00 a0 e1 10 80 bd e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}