
rule HackTool_Linux_Keimpx_A{
	meta:
		description = "HackTool:Linux/Keimpx.A,SIGNATURE_TYPE_CMDHSTR_EXT,18 00 18 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 00 79 00 74 00 68 00 6f 00 6e 00 } //14 00 
		$a_00_1 = {6b 00 65 00 69 00 6d 00 70 00 78 00 } //01 00 
		$a_00_2 = {2d 00 75 00 20 00 } //01 00 
		$a_00_3 = {2d 00 70 00 20 00 } //01 00 
		$a_00_4 = {2d 00 74 00 20 00 } //00 00 
	condition:
		any of ($a_*)
 
}