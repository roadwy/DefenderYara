
rule VirTool_Win32_CeeInject_RW_bit{
	meta:
		description = "VirTool:Win32/CeeInject.RW!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b f8 a5 a5 a5 a4 50 ff 15 ?? ?? ?? ?? 0f bf 05 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 7d 0a c7 05 ?? ?? ?? ?? 61 00 00 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 0f bf 05 ?? ?? ?? ?? 0f bf 15 ?? ?? ?? ?? 3b c2 7e 0a c7 05 ?? ?? ?? ?? 9b 00 00 00 33 c0 83 c4 10 5e 5f c2 0c 00 } //1
		$a_03_1 = {53 56 53 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 45 81 fd 19 10 00 00 72 cc 47 81 ff 15 4f 00 00 73 04 8b ee eb bf 5b 5d 5e 5f c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_CeeInject_RW_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.RW!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b f1 c1 ee ?? 03 35 ?? ?? ?? ?? 8b f9 c1 e7 ?? 03 3d ?? ?? ?? ?? 33 f7 8d 3c 0a 33 f7 2b c6 8b f0 c1 ee ?? 03 35 ?? ?? ?? ?? 8b f8 c1 e7 ?? 03 3d ?? ?? ?? ?? 33 f7 8d 3c 02 33 f7 2b ce 81 c2 } //1
		$a_03_1 = {6a 00 ff 15 ?? ?? ?? ?? 8a 8e ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 88 0c 32 ff d7 46 3b 75 fc } //1
		$a_03_2 = {8b 55 fc 8d 4d f8 51 8b 0d ?? ?? ?? ?? 6a 40 52 51 ff d0 8b 45 fc 8b 35 ?? ?? ?? ?? c1 e8 03 85 c0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}