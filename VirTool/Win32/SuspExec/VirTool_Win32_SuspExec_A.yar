
rule VirTool_Win32_SuspExec_A{
	meta:
		description = "VirTool:Win32/SuspExec.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {77 6d 69 63 2e 65 78 65 } //wmic.exe  1
		$a_80_1 = {50 72 6f 63 65 73 73 20 63 61 6c 6c 20 63 72 65 61 74 65 } //Process call create  1
		$a_02_2 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 [0-20] 5c 00 66 00 69 00 6c 00 65 00 73 00 5c 00 } //1
		$a_02_3 = {5c 57 69 6e 64 6f 77 73 5c 54 45 4d 50 5c [0-20] 5c 66 69 6c 65 73 5c } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}