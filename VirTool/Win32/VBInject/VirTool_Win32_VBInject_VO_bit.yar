
rule VirTool_Win32_VBInject_VO_bit{
	meta:
		description = "VirTool:Win32/VBInject.VO!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 f9 00 75 [0-40] 0f fe f8 [0-20] 8b 40 2c [0-20] 0f ef d7 [0-20] 0f 7e d1 [0-20] 83 f9 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}