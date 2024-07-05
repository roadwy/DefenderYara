
rule Backdoor_Linux_Mirai_IN_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.IN!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {21 28 60 02 21 c8 c0 03 09 f8 20 03 21 30 00 00 18 00 bc 8f 80 00 46 34 04 00 04 24 21 c8 c0 03 09 f8 20 03 21 28 60 02 18 00 bc 8f e0 10 a2 8f } //01 00 
		$a_00_1 = {02 14 06 00 ff ff c3 30 21 18 62 00 02 14 03 00 21 10 43 00 27 10 02 00 08 00 e0 03 ff ff 42 30 } //00 00 
	condition:
		any of ($a_*)
 
}