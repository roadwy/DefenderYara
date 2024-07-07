
rule VirTool_Win32_CeeInject_RV_bit{
	meta:
		description = "VirTool:Win32/CeeInject.RV!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 fc 0f 1f 84 00 00 00 00 00 55 89 e5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule VirTool_Win32_CeeInject_RV_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.RV!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 11 8b 45 90 01 01 03 45 90 01 01 0f b6 08 03 d1 81 e2 90 01 04 79 90 09 09 00 83 c4 90 01 01 8b 4d 90 01 01 03 4d 90 00 } //1
		$a_03_1 = {8b c1 8b d1 03 c6 3b fe 76 08 3b f8 0f 82 90 01 04 83 f9 90 01 01 0f 82 90 01 04 81 f9 90 01 04 73 13 0f ba 25 90 01 04 01 0f 82 90 01 04 e9 90 01 04 0f ba 25 90 01 04 01 73 09 f3 a4 90 00 } //1
		$a_03_2 = {8b 06 03 d0 83 f0 90 01 01 33 c2 8b 16 83 c6 04 a9 90 01 04 74 dc 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}