
rule VirTool_Win32_VBInject_AFL{
	meta:
		description = "VirTool:Win32/VBInject.AFL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 75 08 8b ?? 44 6a 40 68 00 10 00 00 68 d0 17 00 00 ?? 6a ff e8 } //1
		$a_01_1 = {8b c3 99 83 e2 03 03 c2 8b f0 c1 fe 02 81 fe 01 19 00 00 72 06 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}