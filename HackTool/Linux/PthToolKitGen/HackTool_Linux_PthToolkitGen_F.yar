
rule HackTool_Linux_PthToolkitGen_F{
	meta:
		description = "HackTool:Linux/PthToolkitGen.F,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 05 00 00 ffffff9c ffffffff "
		
	strings :
		$a_00_0 = {70 00 79 00 74 00 68 00 6f 00 6e 00 } //9c ff  python
		$a_00_1 = {70 00 65 00 72 00 6c 00 } //01 00  perl
		$a_02_2 = {2d 00 75 00 20 00 90 02 80 25 00 90 01 40 3a 00 90 01 40 20 00 90 00 } //01 00 
		$a_02_3 = {2d 00 2d 00 75 00 73 00 65 00 72 00 3d 00 90 02 80 25 00 90 01 40 3a 00 90 01 40 20 00 90 00 } //05 00 
		$a_00_4 = {2f 00 2f 00 } //00 00  //
	condition:
		any of ($a_*)
 
}