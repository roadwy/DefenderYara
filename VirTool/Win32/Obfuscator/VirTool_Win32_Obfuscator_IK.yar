
rule VirTool_Win32_Obfuscator_IK{
	meta:
		description = "VirTool:Win32/Obfuscator.IK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 46 08 8b 7e 20 8b 36 80 3f 6b 75 f3 80 7f 18 00 } //1
		$a_03_1 = {8a 11 84 d2 74 08 0f be d2 83 c2 ?? eb 02 33 d2 88 11 41 80 39 00 } //1
		$a_01_2 = {c6 40 04 75 c6 40 02 72 c6 40 06 6c c6 40 03 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule VirTool_Win32_Obfuscator_IK_2{
	meta:
		description = "VirTool:Win32/Obfuscator.IK,SIGNATURE_TYPE_PEHSTR_EXT,05 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {ff 54 24 08 89 c7 ff d7 50 ff d7 2b 04 24 85 c0 75 f4 58 e8 19 00 00 00 56 69 72 74 } //1
		$a_01_1 = {ff 54 24 0c 83 ec 04 83 04 24 0a 50 ff 54 24 0c 95 89 68 10 50 83 44 24 f0 15 ff 74 24 f0 } //1
		$a_01_2 = {5f 66 31 ff 8b 07 48 66 31 c0 81 38 4d 5a 90 00 75 f4 6a 70 68 53 6c 65 65 54 50 ff 57 } //1
		$a_03_3 = {8b 40 3c 01 c8 89 c2 8b 98 c0 00 00 00 85 db 60 0f 84 ?? ?? ?? ?? e8 15 00 00 00 54 6c 73 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=1
 
}