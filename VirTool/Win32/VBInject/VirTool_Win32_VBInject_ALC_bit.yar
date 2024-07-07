
rule VirTool_Win32_VBInject_ALC_bit{
	meta:
		description = "VirTool:Win32/VBInject.ALC!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 00 10 40 00 90 02 30 8b 00 90 02 30 bb 00 a9 d5 04 90 02 30 81 c3 00 e7 84 48 90 02 30 0f cb 90 00 } //1
		$a_03_1 = {66 0f ef d1 90 0a 30 00 c3 90 0a 30 00 75 b5 90 0a 30 00 66 0f 7e 14 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}