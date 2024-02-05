
rule Backdoor_Linux_Mirai_AX_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.AX!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 74 6f 72 6d 4d 69 6e 65 63 72 61 66 74 } //01 00 
		$a_01_1 = {4a 48 42 79 70 61 73 73 } //01 00 
		$a_01_2 = {6c 61 63 6b 70 65 6f 70 6c 65 2e 6c 6f 6c 2f 62 69 6e 73 2e 73 68 } //01 00 
		$a_01_3 = {4d 49 52 41 49 } //00 00 
	condition:
		any of ($a_*)
 
}