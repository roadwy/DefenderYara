
rule Backdoor_Linux_Mirai_DU_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DU!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {54 43 50 70 61 79 6c 6f 61 64 54 6f 42 79 74 65 73 } //01 00 
		$a_00_1 = {61 74 74 61 63 6b 5f 67 65 74 5f 6f 70 74 5f 69 70 } //01 00 
		$a_00_2 = {61 74 74 61 63 6b 5f 6d 65 74 68 6f 64 5f 75 64 70 32 66 6c 6f 6f 64 } //01 00 
		$a_00_3 = {61 74 74 61 63 6b 5f 72 65 6d 6f 76 65 5f 69 64 } //00 00 
	condition:
		any of ($a_*)
 
}