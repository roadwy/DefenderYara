
rule HackTool_Linux_PthToolKitGen_A{
	meta:
		description = "HackTool:Linux/PthToolKitGen.A,SIGNATURE_TYPE_CMDHSTR_EXT,10 00 10 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {2d 00 75 00 20 00 90 02 80 25 00 90 00 } //01 00 
		$a_02_1 = {2d 00 2d 00 75 00 73 00 65 00 72 00 3d 00 90 02 80 25 00 90 00 } //0a 00 
		$a_00_2 = {2f 00 2f 00 } //05 00 
		$a_00_3 = {63 00 6d 00 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}