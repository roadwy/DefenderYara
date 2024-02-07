
rule VirTool_Win32_SmbExecCommand{
	meta:
		description = "VirTool:Win32/SmbExecCommand,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 } //01 00 
		$a_00_1 = {20 00 2f 00 43 00 20 00 65 00 63 00 68 00 6f 00 20 00 } //01 00   /C echo 
		$a_00_2 = {20 00 5e 00 3e 00 20 00 } //01 00   ^> 
		$a_00_3 = {20 00 2f 00 43 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 } //01 00   /C start 
		$a_00_4 = {20 00 26 00 20 00 64 00 65 00 6c 00 20 00 } //00 00   & del 
	condition:
		any of ($a_*)
 
}