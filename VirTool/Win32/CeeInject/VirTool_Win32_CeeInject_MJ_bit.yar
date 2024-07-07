
rule VirTool_Win32_CeeInject_MJ_bit{
	meta:
		description = "VirTool:Win32/CeeInject.MJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c2 0f af c1 0f af c1 0f af c6 6a 90 01 01 99 5f f7 ff 8b 7d 90 01 01 01 45 90 01 01 8a c1 32 07 3b f3 75 90 01 01 8a 45 90 01 01 88 07 90 00 } //1
		$a_03_1 = {03 c1 81 c7 90 01 04 41 0f af f1 69 f6 90 01 04 52 ff 75 90 01 01 89 35 90 01 04 ff 75 90 01 01 ff d0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_CeeInject_MJ_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.MJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {b8 0a 00 00 00 6a 00 33 c9 58 f7 f1 } //1
		$a_03_1 = {68 d2 07 00 00 ff 15 90 01 04 ff 15 90 01 04 2b 05 90 01 04 3d 0c 03 00 00 76 90 00 } //1
		$a_01_2 = {b9 a9 6d f1 f3 8b c0 49 75 } //1
		$a_03_3 = {6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 90 01 04 ff 15 90 01 04 8b c8 c1 e1 04 2b c8 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}