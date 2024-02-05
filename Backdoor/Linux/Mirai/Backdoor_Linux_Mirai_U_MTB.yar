
rule Backdoor_Linux_Mirai_U_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.U!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 19 89 d0 01 d8 89 eb 30 18 89 d0 8b 19 01 d8 89 fb 30 18 89 d0 8b 19 01 d8 89 f3 30 18 89 d0 8b 19 42 01 d8 8a 1c 24 30 18 8b 41 04 25 ff ff 00 00 39 d0 7f ca } //01 00 
		$a_00_1 = {4d 45 49 4e 53 4d } //01 00 
		$a_00_2 = {54 53 55 4e 41 4d 49 } //01 00 
		$a_00_3 = {58 4d 48 44 49 50 43 } //01 00 
		$a_00_4 = {54 45 4c 45 43 4f 4d 41 44 4d 49 4e } //00 00 
	condition:
		any of ($a_*)
 
}