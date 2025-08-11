
rule VirTool_Win32_SuspPowerShellCmd_BA{
	meta:
		description = "VirTool:Win32/SuspPowerShellCmd.BA,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {26 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 77 69 6e 64 6f 77 73 70 6f 77 65 72 73 68 65 6c 6c 5c 76 31 2e 30 5c 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //& c:\windows\system32\windowspowershell\v1.0\powershell.exe  1
		$a_80_1 = {2d 65 78 65 63 20 62 79 70 61 73 73 20 2d 63 6f 6d 6d 61 6e 64 20 } //-exec bypass -command   1
		$a_80_2 = {49 4f 2e 46 69 6c 65 53 74 72 65 61 6d 20 27 5c 5c 2e 5c 43 3a 27 } //IO.FileStream '\\.\C:'  1
		$a_80_3 = {27 4f 70 65 6e 27 2c 20 27 52 65 61 64 27 2c 20 27 52 65 61 64 57 72 69 74 65 27 } //'Open', 'Read', 'ReadWrite'  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}