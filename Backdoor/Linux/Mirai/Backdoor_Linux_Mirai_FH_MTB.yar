
rule Backdoor_Linux_Mirai_FH_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.FH!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {92 42 00 00 10 90 01 03 a2 62 00 04 92 50 00 01 26 73 00 08 03 d0 10 2a 26 04 00 01 14 90 01 03 02 d0 90 01 01 21 03 20 f8 09 03 d0 88 23 8f bc 00 18 00 40 20 21 90 00 } //01 00 
		$a_03_1 = {92 03 00 04 8e 02 00 00 a4 a8 ff e8 26 10 00 05 ac a2 ff ec a0 83 ff fc ac 82 ff f8 00 f5 10 2a 24 c6 00 18 24 e7 00 01 24 84 00 18 14 90 01 03 02 86 28 21 02 51 10 21 00 50 18 23 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}