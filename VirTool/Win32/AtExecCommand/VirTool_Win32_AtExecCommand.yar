
rule VirTool_Win32_AtExecCommand{
	meta:
		description = "VirTool:Win32/AtExecCommand,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 43 00 } //01 00 
		$a_00_1 = {3e 00 20 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 } //01 00 
		$a_00_2 = {2e 00 74 00 6d 00 70 00 20 00 32 00 3e 00 26 00 31 00 } //00 00 
	condition:
		any of ($a_*)
 
}