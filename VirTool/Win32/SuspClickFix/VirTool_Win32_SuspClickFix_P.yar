
rule VirTool_Win32_SuspClickFix_P{
	meta:
		description = "VirTool:Win32/SuspClickFix.P,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 } //1 wscript
		$a_00_1 = {20 00 2f 00 2f 00 45 00 3a 00 56 00 42 00 53 00 63 00 72 00 69 00 70 00 74 00 } //1  //E:VBScript
		$a_02_2 = {20 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-20] 5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 [0-40] 5c 00 [0-20] 2e 00 76 00 62 00 73 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}