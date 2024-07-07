
rule VirTool_Win32_VBInject_AED{
	meta:
		description = "VirTool:Win32/VBInject.AED,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 01 58 03 c8 0f 80 90 01 04 89 4b 90 01 01 e9 90 01 03 ff 90 09 03 00 8b 4b 90 00 } //2
		$a_03_1 = {00 be d0 07 00 00 b8 90 01 04 39 43 90 01 01 0f 8f 90 01 02 00 00 90 09 06 00 c7 43 90 01 01 04 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}