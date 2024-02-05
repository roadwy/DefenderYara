
rule VirTool_Win32_SuspServWmiCommand_B{
	meta:
		description = "VirTool:Win32/SuspServWmiCommand.B,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 } //01 00 
		$a_00_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //01 00 
		$a_00_2 = {29 00 2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 } //01 00 
		$a_00_3 = {69 00 65 00 78 00 28 00 } //00 00 
	condition:
		any of ($a_*)
 
}