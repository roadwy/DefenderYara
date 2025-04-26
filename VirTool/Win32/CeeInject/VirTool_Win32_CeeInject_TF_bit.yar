
rule VirTool_Win32_CeeInject_TF_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TF!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b d0 c1 fa 03 8a 14 3a 8a c8 80 e1 07 d2 fa 40 80 e2 01 3b c6 88 54 28 ff 7c e5 } //1
		$a_01_1 = {8a 14 01 30 10 40 83 ee 01 75 f5 } //1
		$a_03_2 = {8b 16 03 54 24 ?? 8b 46 f8 03 44 24 ?? 6a 00 51 8b 4c 24 ?? 52 50 51 ff 54 24 } //1
		$a_03_3 = {52 51 ff d0 85 c0 0f 84 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 8b 54 24 ?? 50 52 ff 54 24 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff d6 50 ff d7 8b 4d ?? 8b 55 ?? 6a 40 68 00 30 00 00 51 8b 4c 24 ?? 52 51 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}