
rule VirTool_Win32_CeeInject_gen_AF{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {75 1a 8b 8d 90 01 02 ff ff 8b 51 34 8b 85 90 01 02 ff ff 03 50 28 89 95 90 01 02 ff ff eb 15 90 00 } //1
		$a_01_1 = {8b 46 28 75 05 03 46 34 eb 03 03 45 fc 89 85 } //1
		$a_01_2 = {be e8 03 00 00 f7 f6 2b ca 89 4d fc 83 7d fc 00 7d 0d 8b 45 fc 05 00 01 00 00 89 45 fc eb ed } //1
		$a_01_3 = {b8 68 58 4d 56 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}