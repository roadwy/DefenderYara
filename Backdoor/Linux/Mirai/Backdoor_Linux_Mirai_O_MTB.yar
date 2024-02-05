
rule Backdoor_Linux_Mirai_O_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.O!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 50 45 41 43 48 } //01 00 
		$a_00_1 = {37 75 6a 4d 6b 6f 30 61 64 6d 69 6e } //01 00 
		$a_00_2 = {70 65 61 63 68 79 20 62 6f 74 6e 65 74 } //01 00 
		$a_00_3 = {6d 65 69 6e 73 6d } //01 00 
		$a_00_4 = {78 6d 68 64 69 70 63 } //00 00 
	condition:
		any of ($a_*)
 
}