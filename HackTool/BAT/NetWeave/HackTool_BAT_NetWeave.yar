
rule HackTool_BAT_NetWeave{
	meta:
		description = "HackTool:BAT/NetWeave,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 65 74 2d 57 65 61 76 65 20 50 6c 75 67 69 6e } //01 00 
		$a_01_1 = {53 74 6f 70 4f 6e 44 69 73 63 6f 6e 6e 65 63 74 69 6f 6e } //01 00 
		$a_01_2 = {44 44 6f 53 65 72 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}