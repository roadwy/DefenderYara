
rule VirTool_Win32_SuspScriptCommand_A{
	meta:
		description = "VirTool:Win32/SuspScriptCommand.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {2f 00 62 00 } //1 /b
		$a_00_1 = {2f 00 65 00 3a 00 6a 00 73 00 63 00 72 00 69 00 70 00 74 00 } //1 /e:jscript
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}