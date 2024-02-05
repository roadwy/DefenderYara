
rule VirTool_Win32_Obfuscator_AQN{
	meta:
		description = "VirTool:Win32/Obfuscator.AQN,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {39 1d 58 54 41 00 74 52 b8 e9 a2 8b 2e f7 6d c0 c1 fa 02 8b c2 c1 e8 1f 03 c2 33 c9 3b c3 7e 10 8b 55 e8 3b d3 0f 84 ad 01 00 00 41 3b c8 7c f3 } //01 00 
		$a_03_1 = {83 7d ec 00 c7 45 f0 00 00 00 00 0f 8e 47 01 00 00 8b 45 f0 8b 4d c8 8a 14 01 a1 44 54 41 00 8b 75 08 50 56 88 55 17 ff 15 90 01 02 40 00 90 00 } //01 00 
		$a_01_2 = {8a c3 32 45 17 85 ff 74 0b 8b 4d c8 8b 55 f0 88 04 11 eb 09 8b 45 c8 8b 4d f0 88 04 08 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}