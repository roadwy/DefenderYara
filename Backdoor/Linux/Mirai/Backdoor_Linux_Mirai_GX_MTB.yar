
rule Backdoor_Linux_Mirai_GX_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.GX!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {24 02 00 01 24 03 00 02 10 90 01 03 ae e2 00 24 14 90 01 03 24 06 00 04 14 90 01 03 26 a4 00 04 10 90 01 03 24 45 00 04 90 00 } //01 00 
		$a_03_1 = {03 20 f8 09 24 06 00 0a 8f bc 00 10 10 90 01 03 00 00 00 00 93 a3 02 64 00 00 00 00 14 90 01 03 24 02 00 05 12 90 01 03 2e 62 00 03 93 a3 02 65 14 40 00 61 24 02 00 05 18 90 01 03 00 60 88 21 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}