
rule VirTool_Win32_VBInject_gen_IX{
	meta:
		description = "VirTool:Win32/VBInject.gen!IX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c7 80 00 05 00 00 5a 5d c3 c3 a1 ?? ?? ?? ?? 89 b0 } //1
		$a_03_1 = {66 8b 04 08 66 03 04 0b 66 8b ce 0f 80 ?? ?? 00 00 66 99 66 f7 f9 0f bf fa 3b fe 72 05 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}