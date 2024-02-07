
rule HackTool_Linux_PthToolkitGen_G{
	meta:
		description = "HackTool:Linux/PthToolkitGen.G,SIGNATURE_TYPE_CMDHSTR_EXT,15 00 15 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 00 6d 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 } //01 00  smbclient
		$a_00_1 = {72 00 70 00 63 00 63 00 6c 00 69 00 65 00 6e 00 74 00 } //14 00  rpcclient
		$a_00_2 = {2d 00 2d 00 70 00 77 00 2d 00 6e 00 74 00 2d 00 68 00 61 00 73 00 68 00 } //00 00  --pw-nt-hash
	condition:
		any of ($a_*)
 
}