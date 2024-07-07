
rule VirTool_Win32_CeeInject_ML_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ML!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 0c b6 b8 90 01 04 c1 e1 90 01 01 2b ce c1 e1 90 01 01 f7 e9 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 8b fa 8d 14 f6 8d 04 d6 8a 4c 3c 90 01 01 c1 e0 90 01 01 03 c6 80 f1 90 01 01 8d 34 c0 b8 90 01 04 f7 ee c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule VirTool_Win32_CeeInject_ML_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.ML!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 55 90 83 c2 01 89 55 90 81 7d 90 88 13 00 00 7d 1c b8 5f 00 00 00 2b 45 98 8b 4d e0 03 c8 89 4d cc } //1
		$a_03_1 = {8b 4d 98 83 c1 01 89 4d 98 81 7d 98 90 01 04 7d 5e 8d 55 a0 52 ff 15 90 01 04 8b 45 b0 03 45 98 33 c9 8a 08 89 4d e0 90 00 } //1
		$a_01_2 = {6a 6b 67 61 61 } //1 jkgaa
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}