
rule VirTool_Win64_Impersonate_B_MTB{
	meta:
		description = "VirTool:Win64/Impersonate.B!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 8b 45 28 4c 8d 45 00 48 8b 4d a0 } //01 00 
		$a_01_1 = {49 6d 70 65 72 73 6f 6e 61 74 65 4c 6f 67 67 65 64 4f 6e 55 73 65 72 } //01 00 
		$a_01_2 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //00 00 
	condition:
		any of ($a_*)
 
}