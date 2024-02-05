
rule VirTool_Win32_Obfuscator_JP{
	meta:
		description = "VirTool:Win32/Obfuscator.JP,SIGNATURE_TYPE_PEHSTR_EXT,06 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {58 fe ff ff 89 90 01 01 f0 90 02 04 00 89 90 01 01 d8 8b 90 01 01 f0 83 90 02 02 89 90 01 01 e4 81 75 fc 38 00 00 00 90 00 } //01 00 
		$a_01_1 = {c7 45 e0 00 00 40 00 83 65 e8 00 83 a5 54 fe ff ff 00 eb } //01 00 
		$a_03_2 = {6a 18 66 89 45 90 01 01 58 6a 06 66 89 45 90 01 01 59 33 c0 8d 7d 90 01 01 f3 ab 8b 45 90 01 01 0f af 45 90 01 01 6b c0 03 90 00 } //02 00 
		$a_03_3 = {24 83 c4 04 29 90 01 01 8b 90 01 01 08 03 90 01 01 f8 c6 90 01 01 00 30 90 01 01 8b 90 01 01 fc 90 01 01 89 90 01 01 fc 83 7d fc 01 75 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}