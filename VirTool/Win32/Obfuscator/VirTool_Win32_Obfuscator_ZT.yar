
rule VirTool_Win32_Obfuscator_ZT{
	meta:
		description = "VirTool:Win32/Obfuscator.ZT,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {29 3d bc 56 41 00 c1 0d 76 54 41 00 03 21 7d c8 6a 36 58 c1 e0 03 8b d8 81 e3 4d 4b 00 00 be 7a 00 00 00 2b } //01 00 
		$a_01_1 = {c1 05 c2 56 41 00 06 d1 eb 31 1d 94 54 41 00 29 1d c5 56 41 00 ba 00 00 00 00 33 d2 6b d2 7d 89 55 b8 68 22 5b 1a 00 5a c1 da 11 } //01 00 
		$a_01_2 = {c1 c9 0c 21 4d fc 29 0d 06 52 41 00 8d 9f 9f 00 00 00 c1 db 19 c1 05 24 52 41 00 05 4b 83 fb 38 75 19 68 da 16 1e 00 8f 05 fc 51 41 00 ff 0d f6 54 41 00 6a 23 8f 05 e8 53 41 00 09 5d c4 be 00 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}