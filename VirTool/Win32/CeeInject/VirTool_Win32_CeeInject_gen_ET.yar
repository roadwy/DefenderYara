
rule VirTool_Win32_CeeInject_gen_ET{
	meta:
		description = "VirTool:Win32/CeeInject.gen!ET,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {56 8b cf 80 f3 90 01 01 e8 90 01 04 46 88 18 83 fe 14 72 e7 90 00 } //1
		$a_01_1 = {f7 b5 a4 00 00 00 8b 45 84 0f b6 04 02 0f b6 55 8b 03 c3 03 d0 23 d1 8b da 90 00 } //1
		$a_01_2 = {40 3d 00 01 00 00 72 f2 33 c9 be ff 00 00 00 33 d2 8b c1 f7 75 14 } //1
		$a_03_3 = {8b 77 3c 68 4d 5a 00 00 50 c7 90 01 02 07 00 01 00 03 f7 e8 90 00 } //1
		$a_01_4 = {ff 45 e4 89 50 f8 0f b7 54 4f 08 89 50 fc c6 00 04 88 58 01 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}