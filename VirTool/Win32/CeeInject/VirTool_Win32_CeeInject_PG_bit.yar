
rule VirTool_Win32_CeeInject_PG_bit{
	meta:
		description = "VirTool:Win32/CeeInject.PG!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 8b 01 66 3d 4d 5a 75 f1 8b 59 3c 03 d9 66 8b 03 66 3d 50 45 75 e3 } //1
		$a_01_1 = {c7 00 56 69 72 74 c7 40 04 75 61 6c 41 c7 40 08 6c 6c 6f 63 } //1
		$a_03_2 = {03 d8 83 c3 ?? 0f b7 40 ?? 8b d0 c1 e2 ?? 8d 14 92 03 da 83 c3 ?? 8b 4b ?? 03 4d ?? 83 c1 ?? 8b 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule VirTool_Win32_CeeInject_PG_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.PG!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e8 ?? 03 05 ?? ?? ?? ?? 8b fa c1 e7 ?? 03 3d ?? ?? ?? ?? 33 c7 8d 3c 16 33 c7 2b c8 8b c1 c1 e8 ?? 03 05 ?? ?? ?? ?? 8b f9 c1 e7 ?? 03 3d ?? ?? ?? ?? 33 c7 8d 3c 0e 2b 75 f8 33 c7 2b d0 ff 4d fc 75 } //1
		$a_03_1 = {56 57 be 20 37 ef c6 e8 ?? ?? ?? ?? 89 45 f8 c7 45 fc 20 00 00 00 } //1
		$a_03_2 = {ff 15 0c c0 ?? 01 8a 86 ?? ?? ?? ?? 88 04 1e ff 15 08 c0 ?? 01 83 fe 0a 75 20 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}