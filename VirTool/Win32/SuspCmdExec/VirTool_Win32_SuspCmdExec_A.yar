
rule VirTool_Win32_SuspCmdExec_A{
	meta:
		description = "VirTool:Win32/SuspCmdExec.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 } //cmd.exe /c  1
		$a_02_1 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 [0-20] 5c 00 [0-60] 2e 00 62 00 61 00 74 00 } //1
		$a_02_2 = {5c 57 69 6e 64 6f 77 73 5c 54 45 4d 50 5c [0-20] 5c [0-60] 2e 62 61 74 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}