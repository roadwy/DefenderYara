
rule VirTool_Win32_Obfuscator_YE{
	meta:
		description = "VirTool:Win32/Obfuscator.YE,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 0c 01 ff 45 fc 8b 55 fc 88 08 8b 4d 18 40 3b 51 50 72 e9 8b 4b 3c 03 cb 8b 81 a0 00 00 00 } //01 00 
		$a_01_1 = {33 d2 6a 5a 59 f7 f1 8b 45 f8 28 14 38 40 89 45 f8 3b 45 f4 72 ea } //01 00 
		$a_01_2 = {8d 0c 10 8d 34 02 8a d9 8b c2 c1 e8 04 24 03 80 e3 1f f6 eb 80 e1 03 f6 e9 b1 fe 2a c8 00 0c 3e ff 45 ec eb c3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_YE_2{
	meta:
		description = "VirTool:Win32/Obfuscator.YE,SIGNATURE_TYPE_PEHSTR_EXT,05 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 05 14 81 40 00 eb 26 00 00 a0 93 94 40 00 c7 05 ce 8b 40 00 9a 08 00 00 3c 25 0f 84 11 00 00 00 0f b7 05 8a 8b 40 00 b8 ff 00 00 00 e9 b9 01 00 00 } //01 00 
		$a_01_1 = {c7 05 00 81 40 00 77 38 00 00 a0 93 94 40 00 3c 25 0f 84 14 00 00 00 b8 ff 00 00 00 c7 05 04 81 40 00 9a 24 00 00 e9 dc 00 00 00 } //01 00 
		$a_01_2 = {a0 93 94 40 00 c7 05 08 81 40 00 97 79 00 00 3c 25 0f 84 0f 00 00 00 b8 a5 0e 00 00 b8 ff 00 00 00 e9 8e 01 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}