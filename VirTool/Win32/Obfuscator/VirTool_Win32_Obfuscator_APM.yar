
rule VirTool_Win32_Obfuscator_APM{
	meta:
		description = "VirTool:Win32/Obfuscator.APM,SIGNATURE_TYPE_PEHSTR_EXT,42 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b cf 83 c1 90 04 01 03 74 2d 76 90 02 18 6a 14 90 02 04 8b 04 30 03 c7 8b f8 90 04 01 03 58 2d 59 90 00 } //5
		$a_01_1 = {8b c6 46 41 8b 00 fe c0 3c 01 75 f4 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule VirTool_Win32_Obfuscator_APM_2{
	meta:
		description = "VirTool:Win32/Obfuscator.APM,SIGNATURE_TYPE_PEHSTR_EXT,42 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 16 8d 45 9c 90 02 18 eb d9 8b 90 01 01 9c ff 90 17 02 02 01 65 9c e2 c7 45 c8 00 00 00 00 8b 4d fc 51 e8 90 01 02 ff ff 5f 5e 5b 8b e5 5d c2 04 00 55 8b ec a1 90 01 02 40 00 5d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule VirTool_Win32_Obfuscator_APM_3{
	meta:
		description = "VirTool:Win32/Obfuscator.APM,SIGNATURE_TYPE_PEHSTR_EXT,42 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b cf 83 c1 77 90 02 18 03 f8 8b 46 14 90 00 } //5
		$a_03_1 = {f3 33 c2 5a 47 90 02 18 e2 90 04 01 03 18 2d 38 90 02 40 ad 4e 4e 4e 75 90 00 } //1
		$a_03_2 = {54 5f 41 89 07 51 58 90 02 10 8b 06 03 f2 89 07 03 fa e2 f6 90 00 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=6
 
}
rule VirTool_Win32_Obfuscator_APM_4{
	meta:
		description = "VirTool:Win32/Obfuscator.APM,SIGNATURE_TYPE_PEHSTR_EXT,42 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b cf 41 83 c1 76 90 02 18 03 f8 8b 46 14 90 00 } //5
		$a_03_1 = {8b cf 41 83 c1 90 04 01 03 74 2d 76 90 02 18 6a 14 8b 04 31 03 c7 8b f8 58 8b 04 30 90 00 } //5
		$a_01_2 = {41 8b 06 fe c0 46 fe c8 75 f6 } //1
		$a_03_3 = {8b c8 41 8b 06 46 3c 00 75 f8 49 89 4d 90 01 01 8b c1 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=6
 
}
rule VirTool_Win32_Obfuscator_APM_5{
	meta:
		description = "VirTool:Win32/Obfuscator.APM,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 8b 46 3c 4f 23 c7 40 8b ce 83 c1 77 03 c1 8b 00 5e 8b fe 03 f0 59 8b 04 31 03 f8 8b 46 14 } //1
		$a_01_1 = {57 8b 47 3c 4a 23 c2 40 8b cf 83 c1 77 03 c1 8b 00 5e 8b fe 03 f0 59 8b 04 31 03 f8 8b 46 14 } //1
		$a_03_2 = {47 8b 47 3b 4a 4f 23 c2 90 02 18 83 c1 77 03 c1 8b 00 5e 8b fe 03 f0 59 90 02 20 8b 04 31 03 f8 8b 46 14 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}