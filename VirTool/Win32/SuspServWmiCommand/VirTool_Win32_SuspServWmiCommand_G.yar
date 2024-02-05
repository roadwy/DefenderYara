
rule VirTool_Win32_SuspServWmiCommand_G{
	meta:
		description = "VirTool:Win32/SuspServWmiCommand.G,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 } //01 00 
		$a_00_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //01 00 
		$a_00_2 = {69 00 65 00 78 00 } //01 00 
		$a_00_3 = {5b 00 73 00 74 00 72 00 69 00 6e 00 67 00 5d 00 28 00 47 00 65 00 74 00 2d 00 57 00 4d 00 49 00 4f 00 62 00 6a 00 65 00 63 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}