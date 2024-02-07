
rule HackTool_Linux_PthToolKitGen_E{
	meta:
		description = "HackTool:Linux/PthToolKitGen.E,SIGNATURE_TYPE_CMDHSTR_EXT,14 00 14 00 04 00 00 05 00 "
		
	strings :
		$a_00_0 = {70 00 79 00 74 00 68 00 6f 00 6e 00 } //05 00  python
		$a_00_1 = {2d 00 2d 00 6c 00 6d 00 3d 00 } //05 00  --lm=
		$a_00_2 = {2d 00 2d 00 6e 00 74 00 3d 00 } //05 00  --nt=
		$a_00_3 = {2d 00 74 00 20 00 } //00 00  -t 
	condition:
		any of ($a_*)
 
}