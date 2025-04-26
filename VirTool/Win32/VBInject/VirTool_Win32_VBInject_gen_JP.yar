
rule VirTool_Win32_VBInject_gen_JP{
	meta:
		description = "VirTool:Win32/VBInject.gen!JP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f6 ff 50 6a 00 6a 00 6a 04 f5 25 00 00 00 04 ?? ff a4 } //1
		$a_03_1 = {f6 77 54 ff 75 fc ff b5 74 f5 35 00 00 00 04 ?? ff a4 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}