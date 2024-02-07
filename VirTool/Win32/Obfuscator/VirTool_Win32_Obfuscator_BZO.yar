
rule VirTool_Win32_Obfuscator_BZO{
	meta:
		description = "VirTool:Win32/Obfuscator.BZO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 0b 8b 45 08 03 45 0c 8a 4d 10 88 08 8b e5 } //01 00 
		$a_01_1 = {eb df 8b 4d 9c ff e1 } //01 00 
		$a_03_2 = {76 30 51 c7 45 90 90 00 00 00 00 eb 09 8b 4d 90 90 83 c1 01 90 00 } //01 00 
		$a_03_3 = {75 45 6a 01 6a 00 ff 15 90 01 04 85 c0 75 13 8d 55 e0 52 a1 90 01 04 50 8b 4d f8 51 e8 90 01 04 8a 55 e0 52 a1 90 01 04 50 8b 4d fc 51 e8 90 01 04 8b 15 90 01 04 83 c2 01 89 15 90 01 04 eb b2 90 00 } //01 00 
		$a_00_4 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}