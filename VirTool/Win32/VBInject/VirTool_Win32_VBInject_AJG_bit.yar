
rule VirTool_Win32_VBInject_AJG_bit{
	meta:
		description = "VirTool:Win32/VBInject.AJG!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 0f 7e 14 08 [0-30] 83 e9 fc [0-20] 81 f9 [0-20] c3 [0-20] 66 0f ef d1 } //1
		$a_03_1 = {b8 00 10 40 00 [0-30] 8b 00 [0-30] bb 00 [0-10] 5a 4d [0-30] 0f cb [0-30] 48 [0-30] 39 18 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}