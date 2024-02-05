
rule Backdoor_Linux_Mirai_DF_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DF!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 6f 6c 66 65 78 65 63 62 69 6e } //01 00 
		$a_01_1 = {50 4c 53 44 49 45 } //01 00 
		$a_01_2 = {6c 6f 6c 66 67 74 } //01 00 
		$a_01_3 = {6f 65 6c 69 6e 75 78 31 32 33 } //01 00 
		$a_01_4 = {74 69 65 73 73 65 61 64 6d } //01 00 
		$a_01_5 = {68 61 63 6b 74 68 65 77 6f 72 6c 64 31 33 33 37 } //00 00 
	condition:
		any of ($a_*)
 
}