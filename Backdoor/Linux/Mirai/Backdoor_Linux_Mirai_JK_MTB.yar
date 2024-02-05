
rule Backdoor_Linux_Mirai_JK_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JK!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {76 61 72 2f 63 6f 77 66 66 78 78 6e 61 } //01 00 
		$a_00_1 = {2f 76 61 72 2f 64 6f 77 6e 6c 6f 61 64 65 72 } //01 00 
		$a_00_2 = {77 35 71 36 68 65 33 64 62 72 73 67 6d 63 6c 6b 69 75 34 74 6f 31 38 6e 70 61 76 6a 37 30 32 66 } //01 00 
		$a_00_3 = {2f 76 61 72 2f 53 6f 66 69 61 } //01 00 
		$a_00_4 = {39 78 73 73 70 6e 76 67 63 38 61 6a 35 70 69 37 6d 32 38 70 } //01 00 
		$a_00_5 = {4d 6f 6f 62 6f 74 } //00 00 
	condition:
		any of ($a_*)
 
}