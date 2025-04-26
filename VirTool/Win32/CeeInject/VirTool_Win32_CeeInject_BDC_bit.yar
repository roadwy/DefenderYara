
rule VirTool_Win32_CeeInject_BDC_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDC!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {8b 5d e0 66 c7 03 55 89 } //1
		$a_01_1 = {8b 4d e0 66 c7 81 be 03 00 00 83 e8 } //1
		$a_01_2 = {8b 5d e0 66 c7 83 c0 03 00 00 04 31 } //1
		$a_01_3 = {8b 5d e0 66 c7 83 c2 03 00 00 37 83 } //1
		$a_01_4 = {8b 55 e0 66 c7 82 c4 03 00 00 c7 04 } //1
		$a_01_5 = {8b 55 e0 66 c7 82 c6 03 00 00 85 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}