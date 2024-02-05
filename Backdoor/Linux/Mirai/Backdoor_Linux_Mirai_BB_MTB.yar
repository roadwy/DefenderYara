
rule Backdoor_Linux_Mirai_BB_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.BB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {54 68 69 73 20 44 65 76 69 63 65 20 48 61 73 20 42 65 65 6e 20 49 6e 66 65 63 74 65 64 20 62 79 20 53 61 6d 61 65 6c 20 42 6f 74 6e 65 74 20 4d 61 64 65 20 42 79 20 75 72 30 61 20 3a 29 } //01 00 
		$a_00_1 = {69 6e 66 65 63 74 65 64 2e 6c 6f 67 } //01 00 
		$a_00_2 = {53 61 6d 61 65 6c 2d 44 44 6f 53 2d 41 74 74 61 63 6b } //01 00 
		$a_00_3 = {42 30 54 4b 31 4c 4c } //00 00 
	condition:
		any of ($a_*)
 
}