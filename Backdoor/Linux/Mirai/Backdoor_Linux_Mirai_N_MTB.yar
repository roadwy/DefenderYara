
rule Backdoor_Linux_Mirai_N_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.N!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 70 72 6f 63 2f 63 70 75 69 6e 66 6f } //01 00 
		$a_00_1 = {61 74 74 61 63 6b 5f 75 64 70 67 61 6d 65 20 } //01 00 
		$a_00_2 = {61 74 74 61 63 6b 5f 67 65 74 5f 6f 70 74 5f 69 6e 74 } //01 00 
		$a_00_3 = {61 74 74 61 63 6b 5f 74 63 70 61 6c 6c 20 } //01 00 
		$a_00_4 = {61 74 74 61 63 6b 5f 76 6f 6c 74 75 64 70 20 } //01 00 
		$a_00_5 = {61 74 74 61 63 6b 5f 74 63 70 75 72 67 } //01 00 
		$a_00_6 = {73 63 61 6e 6e 65 72 5f 69 6e 69 74 } //00 00 
	condition:
		any of ($a_*)
 
}