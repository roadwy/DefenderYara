
rule VirTool_Win32_CeeInject_OA_bit{
	meta:
		description = "VirTool:Win32/CeeInject.OA!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 02 8b 44 24 90 01 01 09 c0 8b 54 24 90 01 01 09 d2 8b 74 24 90 01 01 89 54 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 88 1c 06 81 e1 90 01 04 89 4c 24 90 01 01 eb 90 00 } //1
		$a_03_1 = {89 e1 8b 54 24 90 01 01 89 51 0c 8b 74 24 90 01 01 89 71 04 89 01 c7 41 08 90 01 04 8b 44 24 90 01 01 ff d0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_CeeInject_OA_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.OA!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0c 31 83 f9 3d 7f 14 74 5e 83 e9 2b 74 4f 83 e9 04 74 4f 49 83 e9 0a 72 33 eb 4f } //1
		$a_01_1 = {64 8b 05 30 00 00 00 8b 40 0c 8b 40 0c 8b 00 8b 00 8b 40 18 } //1
		$a_03_2 = {6a 40 68 00 30 00 00 8b 85 90 01 03 ff 50 8b 85 90 01 03 ff 50 ff 15 90 01 03 00 89 45 fc 83 7d fc 00 75 19 6a 40 68 00 30 00 00 8b 85 90 01 03 ff 50 6a 00 ff 15 90 01 03 00 90 00 } //1
		$a_03_3 = {f3 a5 66 81 bd 90 01 03 ff 4d 5a 0f 85 90 01 03 00 a1 90 01 03 00 33 d2 52 50 8b 85 90 01 03 ff 99 03 04 90 01 01 13 54 90 01 02 83 c4 08 8b f0 8d bd 04 ff ff ff b9 3e 00 00 00 f3 a5 81 bd 04 ff ff ff 50 45 00 00 0f 85 90 01 03 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}