
rule Backdoor_Linux_Mirai_AD_xp{
	meta:
		description = "Backdoor:Linux/Mirai.AD!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 69 6c 6c 65 64 20 74 6d 70 } //01 00 
		$a_01_1 = {65 78 65 5f 6b 69 6c 6c } //01 00 
		$a_01_2 = {6b 69 6c 6c 5f 6d 61 70 73 } //01 00 
		$a_01_3 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //00 00 
		$a_00_4 = {5d 04 00 } //00 68 
	condition:
		any of ($a_*)
 
}