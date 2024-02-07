
rule VirTool_Win32_SuspServWmiCommand_E{
	meta:
		description = "VirTool:Win32/SuspServWmiCommand.E,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 } //01 00  cmd
		$a_00_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //01 00  powershell
		$a_00_2 = {6e 00 65 00 74 00 73 00 68 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 61 00 64 00 64 00 20 00 70 00 6f 00 72 00 74 00 6f 00 70 00 65 00 6e 00 69 00 6e 00 67 00 } //01 00  netsh firewall add portopening
		$a_00_3 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 } //00 00  schtasks /create
	condition:
		any of ($a_*)
 
}