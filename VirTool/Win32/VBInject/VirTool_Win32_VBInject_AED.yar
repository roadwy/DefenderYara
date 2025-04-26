
rule VirTool_Win32_VBInject_AED{
	meta:
		description = "VirTool:Win32/VBInject.AED,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 01 58 03 c8 0f 80 ?? ?? ?? ?? 89 4b ?? e9 ?? ?? ?? ff 90 09 03 00 8b 4b } //2
		$a_03_1 = {00 be d0 07 00 00 b8 ?? ?? ?? ?? 39 43 ?? 0f 8f ?? ?? 00 00 90 09 06 00 c7 43 ?? 04 00 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}