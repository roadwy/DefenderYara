
rule VirTool_Win32_SuspRemoteCmdCommand_F{
	meta:
		description = "VirTool:Win32/SuspRemoteCmdCommand.F,SIGNATURE_TYPE_CMDHSTR_EXT,09 00 09 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 } //02 00 
		$a_00_1 = {20 00 2f 00 63 00 20 00 65 00 63 00 68 00 6f 00 20 00 } //02 00 
		$a_00_2 = {20 00 5e 00 3e 00 20 00 } //02 00 
		$a_02_3 = {20 00 3e 00 20 00 90 02 08 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 90 02 20 2e 00 62 00 61 00 74 00 90 00 } //01 00 
		$a_00_4 = {20 00 26 00 20 00 64 00 65 00 6c 00 20 00 } //00 00 
	condition:
		any of ($a_*)
 
}