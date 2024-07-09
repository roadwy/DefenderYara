
rule VirTool_Win32_CeeInject_gen_JV{
	meta:
		description = "VirTool:Win32/CeeInject.gen!JV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 ff 77 50 ff 77 34 ff 75 ?? ff 95 ?? ?? ff ff } //1
		$a_01_1 = {ff b4 08 08 01 00 00 8b 94 08 0c 01 00 00 8d 84 08 f8 00 00 00 03 d1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}