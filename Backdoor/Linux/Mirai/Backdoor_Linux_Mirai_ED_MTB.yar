
rule Backdoor_Linux_Mirai_ED_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.ED!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {00 38 f7 f1 29 04 a2 a6 db 3b 60 8d a0 6c 34 da b4 3a 80 f4 31 02 89 34 73 19 88 be 99 5f 98 0e 32 54 ae 03 d6 12 0f 27 80 42 05 de d8 5e b4 e0 a6 40 cd 53 f6 2e 9c 2a 07 36 5b fa 9f 7c f0 2e cb 1a 53 8d 95 7a 07 9f 4f 12 df a9 0f 66 40 d3 84 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}