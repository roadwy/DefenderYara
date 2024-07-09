
rule VirTool_Win32_VBInject_VL_bit{
	meta:
		description = "VirTool:Win32/VBInject.VL!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {81 78 04 ec 0c 56 8d 0f 85 ?? ?? ?? ?? e9 } //2
		$a_03_1 = {83 f8 00 74 [0-20] 81 38 ?? ?? ?? ?? 75 ?? e9 ?? ?? ?? 00 } //2
		$a_03_2 = {3b 7d 3c 0f 85 ?? ?? ?? ff } //1
		$a_01_3 = {68 00 20 00 00 8f 45 3c } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}