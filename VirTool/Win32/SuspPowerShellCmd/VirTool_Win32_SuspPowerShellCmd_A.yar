
rule VirTool_Win32_SuspPowerShellCmd_A{
	meta:
		description = "VirTool:Win32/SuspPowerShellCmd.A,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //powershell.exe  1
		$a_80_1 = {20 62 79 70 61 73 73 } // bypass  1
		$a_02_2 = {20 00 2d 00 46 00 69 00 6c 00 65 00 20 00 [0-10] 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 } //1
		$a_02_3 = {20 2d 46 69 6c 65 20 [0-10] 5c 57 69 6e 64 6f 77 73 5c 54 45 4d 50 5c } //1
		$a_02_4 = {20 00 2d 00 45 00 72 00 72 00 6f 00 72 00 4c 00 6f 00 67 00 46 00 69 00 6c 00 65 00 20 00 [0-10] 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 } //1
		$a_02_5 = {20 2d 45 72 72 6f 72 4c 6f 67 46 69 6c 65 20 [0-10] 5c 57 69 6e 64 6f 77 73 5c 54 45 4d 50 5c } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1) >=4
 
}