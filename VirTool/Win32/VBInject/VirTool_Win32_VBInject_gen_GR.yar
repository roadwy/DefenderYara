
rule VirTool_Win32_VBInject_gen_GR{
	meta:
		description = "VirTool:Win32/VBInject.gen!GR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {28 44 ff 38 00 04 34 ff 0a ?? 00 08 00 04 34 ff fb ef 14 ff 28 f4 fe 42 00 } //2
		$a_03_1 = {fb 12 fc 0d 6c ?? ?? 6c ?? ?? fc a0 } //1
		$a_03_2 = {f5 03 00 00 00 6c ?? ?? 52 fe c1 ?? ?? 40 00 00 00 90 09 08 00 fe c1 ?? ?? 00 30 00 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}