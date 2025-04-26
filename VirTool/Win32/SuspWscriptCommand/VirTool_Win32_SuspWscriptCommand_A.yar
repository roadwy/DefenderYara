
rule VirTool_Win32_SuspWscriptCommand_A{
	meta:
		description = "VirTool:Win32/SuspWscriptCommand.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 } //1 wscript
		$a_00_1 = {2f 00 62 00 } //1 /b
		$a_00_2 = {2f 00 65 00 3a 00 6a 00 73 00 63 00 72 00 69 00 70 00 74 00 } //1 /e:jscript
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}