
rule VirTool_Win32_CeeInject_MZ_bit{
	meta:
		description = "VirTool:Win32/CeeInject.MZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 4d ff 30 0c 30 40 3b 07 7c f5 } //1
		$a_03_1 = {e8 b9 86 00 00 99 b9 17 00 00 00 f7 f9 8d b5 90 01 04 8d 5a 61 e8 90 01 04 4f 75 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_CeeInject_MZ_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.MZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_03_0 = {64 8b 01 e9 90 01 03 00 90 00 } //1
		$a_03_1 = {8b 40 0c 8b 40 0c e9 90 01 03 00 90 00 } //1
		$a_03_2 = {8b 40 18 89 04 24 e9 90 01 03 00 90 00 } //1
		$a_03_3 = {83 65 fc 00 03 c1 8b 78 1c 8b 58 24 8b 70 20 8b 40 18 03 f9 e9 90 01 03 00 90 00 } //1
		$a_03_4 = {0f be 3a 03 cf 33 f1 42 e9 90 01 03 ff 90 00 } //2
		$a_03_5 = {68 22 02 bf 8a 57 e8 90 01 03 00 8b d8 e9 90 01 03 00 90 00 } //3
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*2+(#a_03_5  & 1)*3) >=4
 
}