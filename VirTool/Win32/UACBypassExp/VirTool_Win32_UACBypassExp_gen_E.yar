
rule VirTool_Win32_UACBypassExp_gen_E{
	meta:
		description = "VirTool:Win32/UACBypassExp.gen!E,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 70 00 79 00 74 00 68 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_00_1 = {5c 00 70 00 79 00 74 00 68 00 6f 00 6e 00 77 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_00_2 = {2e 00 70 00 79 00 } //2 .py
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2) >=3
 
}