
rule VirTool_Win32_VBInject_gen_GV{
	meta:
		description = "VirTool:Win32/VBInject.gen!GV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f3 8b 00 fc 0d f5 00 00 00 00 04 4c ff fc a0 f4 4c fc 0d f5 01 00 00 00 04 4c ff fc a0 f4 24 fc } //1
		$a_03_1 = {f5 03 00 00 00 6c ?? ?? 52 fe c1 ?? ?? 40 00 00 00 90 09 08 00 fe c1 ?? ?? 00 30 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}