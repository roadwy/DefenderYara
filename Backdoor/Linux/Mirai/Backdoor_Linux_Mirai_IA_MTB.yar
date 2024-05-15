
rule Backdoor_Linux_Mirai_IA_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.IA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 06 11 42 00 02 10 80 00 45 10 21 8c 43 00 38 00 c4 20 04 00 64 18 25 02 46 28 2a 10 90 01 03 ac 43 00 38 00 c0 90 01 01 21 8f a2 00 2c 00 00 00 00 24 45 00 01 28 a3 01 3c 10 90 01 03 af a5 00 2c 90 00 } //01 00 
		$a_03_1 = {24 42 00 01 30 42 00 ff 10 90 01 03 a2 02 32 1c 02 60 c8 21 03 20 f8 09 02 00 20 21 8f a2 00 2c 8f bc 00 18 24 45 00 01 28 a3 01 3c 14 90 01 03 af a5 00 2c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}