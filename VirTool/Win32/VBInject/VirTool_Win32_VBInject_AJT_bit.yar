
rule VirTool_Win32_VBInject_AJT_bit{
	meta:
		description = "VirTool:Win32/VBInject.AJT!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {a1 00 10 40 00 [0-30] 48 [0-30] 81 38 4d 5a [0-30] 75 } //1
		$a_03_1 = {66 0f 7e 14 08 [0-30] 83 e9 fc [0-30] 81 f9 [0-30] 75 [0-30] c3 [0-30] 66 0f ef d1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}