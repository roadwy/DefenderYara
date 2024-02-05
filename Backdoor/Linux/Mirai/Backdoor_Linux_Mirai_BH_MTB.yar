
rule Backdoor_Linux_Mirai_BH_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.BH!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 19 89 d0 01 d8 89 eb 30 18 89 d0 8b 19 01 d8 89 fb 30 18 89 d0 8b 19 01 d8 89 f3 30 18 89 d0 8b 19 42 01 d8 8a 1c 24 30 18 8b 41 04 25 ff ff 00 00 39 d0 7f ca } //01 00 
		$a_00_1 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //01 00 
		$a_00_2 = {8b 14 08 89 53 10 8b 54 08 0c 66 89 53 14 } //01 00 
		$a_00_3 = {c7 43 34 00 00 00 00 89 43 30 c6 43 38 01 c6 43 39 03 c6 43 3a 03 } //00 00 
	condition:
		any of ($a_*)
 
}