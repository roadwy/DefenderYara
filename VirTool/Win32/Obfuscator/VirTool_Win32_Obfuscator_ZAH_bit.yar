
rule VirTool_Win32_Obfuscator_ZAH_bit{
	meta:
		description = "VirTool:Win32/Obfuscator.ZAH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 8a 4c 37 04 8a 14 02 8a c3 f6 d0 88 0e a8 01 74 04 02 ca eb 02 2a ca 88 0e 43 8b 4d 90 01 01 46 3b 5d fc 72 d4 90 00 } //01 00 
		$a_03_1 = {b8 4d 5a 00 00 89 7d fc 8b 5f 90 01 01 89 5d f4 66 39 03 74 07 32 c0 e9 90 01 02 00 00 56 8b 73 3c 03 f3 81 3e 50 45 00 00 0f 85 90 01 02 00 00 90 00 } //01 00 
		$a_03_2 = {6a 40 68 00 30 00 00 52 6a 00 ff 17 8b f8 85 ff 0f 84 90 01 02 00 00 0f b7 46 06 6b c8 28 0f b7 46 14 03 c8 8b 43 3c 83 c1 18 03 c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}