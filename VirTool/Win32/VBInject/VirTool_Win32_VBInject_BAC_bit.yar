
rule VirTool_Win32_VBInject_BAC_bit{
	meta:
		description = "VirTool:Win32/VBInject.BAC!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 7a 0a 14 00 [0-20] 05 dc f5 2d 00 [0-20] 39 01 [0-20] 0f 85 5a ff ff ff [0-20] 83 e9 04 [0-20] 68 3c 9f 24 00 [0-20] 58 [0-20] 05 11 61 2e 00 [0-20] 8b 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}