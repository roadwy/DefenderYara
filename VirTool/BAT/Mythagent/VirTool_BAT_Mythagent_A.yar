
rule VirTool_BAT_Mythagent_A{
	meta:
		description = "VirTool:BAT/Mythagent.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 70 6f 6c 6c 6f 2e 45 76 61 73 69 6f 6e } //01 00 
		$a_01_1 = {41 70 6f 6c 6c 6f 2e 4a 6f 62 73 } //01 00 
		$a_01_2 = {41 70 6f 6c 6c 6f 2e 43 6f 6d 6d 61 6e 64 4d 6f 64 75 6c 65 73 } //01 00 
		$a_01_3 = {4d 79 74 68 69 63 2e 43 32 50 72 6f 66 69 6c 65 73 } //01 00 
		$a_01_4 = {4d 79 74 68 69 63 53 65 72 76 65 72 52 65 73 70 6f 6e 73 65 } //00 00 
	condition:
		any of ($a_*)
 
}