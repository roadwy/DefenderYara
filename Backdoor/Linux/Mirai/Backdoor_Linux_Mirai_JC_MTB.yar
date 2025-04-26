
rule Backdoor_Linux_Mirai_JC_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JC!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 26 80 80 40 2c 84 10 ca 22 8e 01 52 27 7e 80 60 81 ca 24 82 10 4a ?? 82 25 20 00 68 74 d8 72 } //1
		$a_03_1 = {00 17 89 00 04 21 8b 1f 00 00 c0 00 52 23 fe 91 e8 ?? 96 6c 44 21 c9 1f 42 23 43 00 40 2e 46 01 21 74 40 27 47 00 40 2e 49 00 06 24 4c 12 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}