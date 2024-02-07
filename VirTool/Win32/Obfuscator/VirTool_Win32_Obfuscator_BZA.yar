
rule VirTool_Win32_Obfuscator_BZA{
	meta:
		description = "VirTool:Win32/Obfuscator.BZA,SIGNATURE_TYPE_PEHSTR_EXT,32 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8b 4d 0c 2b c8 8a 14 01 8a 18 32 da 88 18 40 4e 75 } //01 00 
		$a_01_1 = {40 48 60 83 e8 0a 83 c0 0a 61 } //01 00 
		$a_03_2 = {33 c0 c6 45 90 01 01 46 c6 45 90 01 01 75 c6 45 90 01 01 63 c6 45 90 01 01 6b 90 00 } //00 00 
		$a_00_3 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}