
rule HackTool_Linux_PTHToolkitGenC_EE{
	meta:
		description = "HackTool:Linux/PTHToolkitGenC.EE,SIGNATURE_TYPE_CMDHSTR_EXT,79 00 15 00 07 00 00 14 00 "
		
	strings :
		$a_00_0 = {73 00 6d 00 62 00 20 00 } //01 00 
		$a_00_1 = {2d 00 75 00 20 00 } //01 00 
		$a_00_2 = {2d 00 69 00 64 00 20 00 } //01 00 
		$a_00_3 = {2d 00 78 00 20 00 } //01 00 
		$a_00_4 = {2d 00 6b 00 20 00 } //01 00 
		$a_00_5 = {2d 00 2d 00 6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 } //01 00 
		$a_00_6 = {2d 00 6c 00 6f 00 63 00 61 00 6c 00 2d 00 61 00 75 00 74 00 68 00 } //00 00 
	condition:
		any of ($a_*)
 
}