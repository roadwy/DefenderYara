
rule VirTool_Win32_Obfuscator_PN{
	meta:
		description = "VirTool:Win32/Obfuscator.PN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {9f ff ff 2b c8 03 4d f8 89 4d f8 8b 45 f8 90 09 02 00 b9 } //1
		$a_03_1 = {05 00 5a 00 00 [0-10] 33 c7 66 3b 46 20 5f 5e 5b 0f 84 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_Obfuscator_PN_2{
	meta:
		description = "VirTool:Win32/Obfuscator.PN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8d 6c 24 ?? 81 ec } //1
		$a_03_1 = {8d 7e 14 8b 37 8b d8 eb 90 14 3b f7 75 ?? 33 c0 5f 5b 5e c9 c2 04 00 8b 46 10 eb f4 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_Obfuscator_PN_3{
	meta:
		description = "VirTool:Win32/Obfuscator.PN,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 73 61 72 74 79 73 61 69 64 } //1 Usartysaid
		$a_01_1 = {2c 6a 0c 63 88 44 24 } //1
		$a_01_2 = {be d6 43 d2 7d 23 8f 55 04 93 5d e0 3b d3 95 94 } //2
		$a_03_3 = {8d 04 0a 8a d1 80 e2 03 c1 e8 04 f6 ea b2 fe 2a d0 00 14 0f ff 45 ?? 8b 55 ?? eb ?? 8b 45 ?? 83 c1 20 3b c8 72 ?? 8b 45 ?? 33 c9 85 c0 74 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_03_3  & 1)*2) >=2
 
}
rule VirTool_Win32_Obfuscator_PN_4{
	meta:
		description = "VirTool:Win32/Obfuscator.PN,SIGNATURE_TYPE_PEHSTR_EXT,64 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 80 94 01 00 00 8b 00 03 41 3c 8b (4d 14|4c 24 18) 8b 89 90 03 01 01 d4 d8 01 00 00 8b 49 14 6a 04 68 00 30 00 00 ff 70 50 6a 00 ff d1 } //10
		$a_03_1 = {3a c8 75 0f 8d 45 ?? e8 ?? ?? ff ff 8b 4d ?? 3b c1 74 ?? 8b 45 fc } //1
		$a_03_2 = {8a 0a 80 f9 ?? 75 ?? c6 00 00 8b 86 88 01 00 00 03 c7 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=11
 
}