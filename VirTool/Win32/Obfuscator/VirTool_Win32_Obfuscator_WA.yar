
rule VirTool_Win32_Obfuscator_WA{
	meta:
		description = "VirTool:Win32/Obfuscator.WA,SIGNATURE_TYPE_PEHSTR_EXT,07 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 0f b7 49 16 35 90 01 04 05 90 00 } //01 00 
		$a_01_1 = {ff 70 50 6a 00 ff d1 89 45 fc 8b 45 f8 } //01 00 
		$a_03_2 = {88 01 41 42 8a 02 3c 90 09 06 00 eb 08 34 90 01 01 2c 90 00 } //01 00 
		$a_01_3 = {8b 45 fc 8b 41 3c 03 c1 89 45 } //02 00 
		$a_01_4 = {c7 45 d4 58 50 58 41 c7 45 d8 58 43 58 4b } //00 00 
	condition:
		any of ($a_*)
 
}