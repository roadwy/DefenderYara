
rule Backdoor_Linux_Mirai_KS_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.KS!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 85 99 8f e0 00 b0 af 09 f8 20 03 b0 00 a4 27 10 00 bc 8f 8f 01 40 04 21 18 40 00 f4 00 a2 93 00 00 00 00 19 00 40 10 21 80 03 02 d4 00 a3 8f fe ff 02 24 08 00 62 14 00 00 00 00 00 00 82 8e 11 00 00 10 04 00 94 26 } //1
		$a_01_1 = {45 00 a2 93 ff ff 84 34 01 00 42 30 01 00 03 24 45 00 a2 a3 3c 00 a4 af f0 00 a4 af f4 00 a3 a3 f5 00 a0 a3 a4 85 82 8f 00 00 03 92 00 00 44 8c 40 10 03 00 21 10 44 00 00 00 42 94 00 00 00 00 20 00 42 30 0e 00 40 10 25 00 02 24 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}