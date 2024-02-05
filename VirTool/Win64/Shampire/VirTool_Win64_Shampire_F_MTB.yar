
rule VirTool_Win64_Shampire_F_MTB{
	meta:
		description = "VirTool:Win64/Shampire.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {45 6d 70 69 72 65 } //01 00 
		$a_81_1 = {43 53 68 61 72 70 50 79 } //01 00 
		$a_81_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //01 00 
		$a_81_3 = {49 72 6f 6e 50 79 74 68 6f 6e 2e 48 6f 73 74 69 6e 67 } //01 00 
		$a_81_4 = {49 72 6f 6e 50 79 74 68 6f 6e 2e 53 51 4c 69 74 65 } //01 00 
		$a_81_5 = {41 67 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}