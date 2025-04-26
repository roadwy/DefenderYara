
rule VirTool_Win32_SilentCleanupUACBypass_B{
	meta:
		description = "VirTool:Win32/SilentCleanupUACBypass.B,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6c 00 65 00 61 00 6e 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00 20 00 2f 00 61 00 75 00 74 00 6f 00 63 00 6c 00 65 00 61 00 6e 00 } //1 \cmd.exe \system32\cleanmgr.exe /autoclean
		$a_00_1 = {20 00 2f 00 64 00 20 00 } //1  /d 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}