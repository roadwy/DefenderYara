
rule VirTool_Win32_VBInject_AJT_bit{
	meta:
		description = "VirTool:Win32/VBInject.AJT!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {a1 00 10 40 00 90 02 30 48 90 02 30 81 38 4d 5a 90 02 30 75 90 00 } //1
		$a_03_1 = {66 0f 7e 14 08 90 02 30 83 e9 fc 90 02 30 81 f9 90 02 30 75 90 02 30 c3 90 02 30 66 0f ef d1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}