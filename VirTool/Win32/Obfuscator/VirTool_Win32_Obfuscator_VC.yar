
rule VirTool_Win32_Obfuscator_VC{
	meta:
		description = "VirTool:Win32/Obfuscator.VC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 9c 80 0c 24 01 9d 0f 82 90 16 46 9c 80 0c 24 01 9d 0f 82 90 16 8b 83 ?? ?? ?? 00 9c 80 0c 24 01 9d 0f 82 90 16 03 83 ?? ?? ?? 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule VirTool_Win32_Obfuscator_VC_2{
	meta:
		description = "VirTool:Win32/Obfuscator.VC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b7 44 78 fe 04 80 88 45 f7 [0-20] eb 90 14 8d 45 f0 0f b6 55 f7 32 d3 b9 00 00 00 00 } //1
		$a_01_1 = {8b 02 3d 92 00 00 c0 7f 2c 74 5c } //1
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule VirTool_Win32_Obfuscator_VC_3{
	meta:
		description = "VirTool:Win32/Obfuscator.VC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff d0 4a 75 83 50 58 60 8b } //1
		$a_01_1 = {fe c0 f6 d8 04 9d fe c0 d0 c8 fc 90 aa 49 0f } //1
		$a_01_2 = {ac 8b d2 fc 09 c0 d0 c8 f6 d8 34 e1 fc d0 c0 fe c0 d0 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule VirTool_Win32_Obfuscator_VC_4{
	meta:
		description = "VirTool:Win32/Obfuscator.VC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 f7 57 06 f2 e9 } //1
		$a_01_1 = {68 ce 8a 23 69 e9 } //1
		$a_01_2 = {68 8f b0 e9 11 e9 } //1
		$a_01_3 = {68 60 d8 0d da e9 } //1
		$a_01_4 = {68 d6 25 22 cb e9 } //1
		$a_01_5 = {81 f9 b1 6b 89 31 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}
rule VirTool_Win32_Obfuscator_VC_5{
	meta:
		description = "VirTool:Win32/Obfuscator.VC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0d 00 ff ff ff 40 8a 90 90 ?? ?? ?? ?? 30 14 1e a1 ?? ?? ?? ?? 46 3b f0 72 8b a1 ?? ?? ?? ?? 6a 00 6a 00 6a 03 6a 00 6a 03 68 00 00 00 80 } //1
		$a_02_1 = {8a 04 2a 33 d2 8a d3 03 d6 03 c2 25 ff 00 00 00 8b f0 8a 86 ?? ?? ?? ?? 88 81 ?? ?? ?? ?? 41 81 f9 00 01 00 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule VirTool_Win32_Obfuscator_VC_6{
	meta:
		description = "VirTool:Win32/Obfuscator.VC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {bb 00 00 00 00 b9 04 00 00 00 53 e2 fd 68 ?? ?? ?? ?? 53 53 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? bb 00 00 00 00 53 53 53 53 68 ?? ?? ?? ?? 53 53 e8 } //1
		$a_02_1 = {56 6a 01 e8 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 02 75 f0 eb 19 46 50 83 c0 78 48 b8 ?? ?? ?? ?? c7 00 00 00 00 00 58 e2 d3 e9 f7 d6 ff ff 59 5e a1 ?? ?? ?? ?? 8a 1e 32 d8 88 1e } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}