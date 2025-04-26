
rule VirTool_Win32_VBInject_AFV{
	meta:
		description = "VirTool:Win32/VBInject.AFV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 80 2f 01 00 00 8b ?? eb d1 ?? c2 41 00 00 ?? 6a 08 ff ?? 70 e8 } //1
		$a_03_1 = {b8 b8 0b 00 00 3b ?? 7f 26 8b ?? c1 e0 04 03 ?? 44 50 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}