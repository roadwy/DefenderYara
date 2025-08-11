
rule VirTool_Win32_SuspPowerShellCmd_BL{
	meta:
		description = "VirTool:Win32/SuspPowerShellCmd.BL,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_80_0 = {26 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 77 69 6e 64 6f 77 73 70 6f 77 65 72 73 68 65 6c 6c 5c 76 31 2e 30 5c 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //& c:\windows\system32\windowspowershell\v1.0\powershell.exe  3
		$a_80_1 = {2d 65 78 65 63 20 62 79 70 61 73 73 20 2d 63 6f 6d 6d 61 6e 64 20 } //-exec bypass -command   3
		$a_80_2 = {73 65 74 2d 70 73 72 65 61 64 6c 69 6e 65 6f 70 74 69 6f 6e } //set-psreadlineoption  3
		$a_80_3 = {2d 68 69 73 74 6f 72 79 73 61 76 65 73 74 79 6c 65 20 73 61 76 65 6e 6f 74 68 69 6e 67 } //-historysavestyle savenothing  1
		$a_80_4 = {2d 68 69 73 74 6f 72 79 73 61 76 65 70 61 74 68 20 24 7b 74 65 6d 70 7d 2f } //-historysavepath ${temp}/  1
		$a_80_5 = {2d 6d 61 78 69 6d 75 6d 68 69 73 74 6f 72 79 63 6f 75 6e 74 20 31 } //-maximumhistorycount 1  1
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=10
 
}