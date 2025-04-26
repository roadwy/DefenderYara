
rule Backdoor_Linux_Mirai_GM_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.GM!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {14 00 67 20 b6 28 00 04 67 18 43 e8 00 06 42 81 52 81 b2 82 67 0e 20 49 10 29 00 04 5c 89 b6 00 66 ee 28 10 20 44 20 08 4c df 00 1c 4e 75 } //1
		$a_00_1 = {d1 ef 00 30 20 03 d0 8a 20 92 11 6a 00 04 00 04 5a 8a 5b 82 31 7c 00 02 ff f0 21 50 ff f4 41 e8 00 16 b0 8a 66 e2 4a 82 66 46 99 cc 4a af 00 30 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}