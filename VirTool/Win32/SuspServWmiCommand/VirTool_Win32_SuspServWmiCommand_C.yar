
rule VirTool_Win32_SuspServWmiCommand_C{
	meta:
		description = "VirTool:Win32/SuspServWmiCommand.C,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 } //01 00  cmd
		$a_00_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //01 00  powershell
		$a_00_2 = {73 00 76 00 20 00 } //01 00  sv 
		$a_00_3 = {29 00 2e 00 76 00 61 00 6c 00 75 00 65 00 2e 00 74 00 6f 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 29 00 } //00 00  ).value.toString()
	condition:
		any of ($a_*)
 
}