
rule VirTool_Win32_SuspRemoteCmdCommand_G{
	meta:
		description = "VirTool:Win32/SuspRemoteCmdCommand.G,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_00_1 = {20 00 31 00 3e 00 20 00 5c 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 5c 00 41 00 44 00 4d 00 49 00 4e 00 24 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 7b 00 } //1  1> \\localhost\ADMIN$\Temp\{
		$a_00_2 = {7d 00 20 00 32 00 3e 00 26 00 31 00 } //1 } 2>&1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}