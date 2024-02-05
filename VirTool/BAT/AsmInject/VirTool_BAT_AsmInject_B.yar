
rule VirTool_BAT_AsmInject_B{
	meta:
		description = "VirTool:BAT/AsmInject.B,SIGNATURE_TYPE_PEHSTR,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 73 53 61 6e 64 62 6f 78 69 65 } //01 00 
		$a_01_1 = {49 73 4e 6f 72 6d 61 6e 53 61 6e 64 62 6f 78 } //01 00 
		$a_01_2 = {49 73 53 75 6e 62 65 6c 74 53 61 6e 64 62 6f 78 } //01 00 
		$a_01_3 = {49 73 41 6e 75 62 69 73 53 61 6e 64 62 6f 78 } //01 00 
		$a_01_4 = {49 73 43 57 53 61 6e 64 62 6f 78 } //01 00 
		$a_01_5 = {49 73 57 69 72 65 73 68 61 72 6b } //00 00 
	condition:
		any of ($a_*)
 
}