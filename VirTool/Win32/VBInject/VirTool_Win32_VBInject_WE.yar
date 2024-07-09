
rule VirTool_Win32_VBInject_WE{
	meta:
		description = "VirTool:Win32/VBInject.WE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {00 68 a1 6a 8b 4d ?? c7 81 ?? ?? 00 00 3d d8 51 e8 } //1
		$a_03_1 = {68 d0 37 10 8b 45 ?? ba ?? ?? ?? ?? c7 80 ?? ?? 00 00 f2 51 e8 d5 } //1
		$a_03_2 = {00 68 88 fe 8b 55 ?? c7 82 ?? ?? 00 00 b3 16 51 e8 } //1
		$a_01_3 = {c1 cf 0d 03 8b 4d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}