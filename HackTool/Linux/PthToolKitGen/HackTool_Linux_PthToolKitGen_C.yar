
rule HackTool_Linux_PthToolKitGen_C{
	meta:
		description = "HackTool:Linux/PthToolKitGen.C,SIGNATURE_TYPE_CMDHSTR_EXT,3c 00 3c 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {70 00 79 00 74 00 68 00 6f 00 6e 00 } //32 00  python
		$a_02_1 = {2d 00 68 00 61 00 73 00 68 00 65 00 73 00 20 00 90 01 40 3a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}