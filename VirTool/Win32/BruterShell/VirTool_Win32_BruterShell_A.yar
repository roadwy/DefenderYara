
rule VirTool_Win32_BruterShell_A{
	meta:
		description = "VirTool:Win32/BruterShell.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 78 05 e8 75 90 01 01 80 78 06 03 75 90 01 01 80 78 0d 8b 75 90 01 01 80 78 0e d4 75 90 01 01 0f b6 50 02 90 00 } //01 00 
		$a_01_1 = {c7 44 24 04 89 4d 39 8c 89 44 24 08 e8 } //01 00 
		$a_03_2 = {89 14 24 c7 44 24 90 01 01 50 4f 53 54 c6 44 24 90 01 01 00 c7 44 24 90 01 01 7b 22 61 72 c7 44 24 90 01 01 63 68 22 3a 90 00 } //01 00 
		$a_03_3 = {c7 44 24 04 aa fc 0d 7c 90 02 80 c7 44 24 04 bd ca 3b d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_BruterShell_A_2{
	meta:
		description = "VirTool:Win32/BruterShell.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 44 24 04 26 25 19 3e 89 44 24 08 c7 04 24 00 00 00 00 e8 } //01 00 
		$a_03_1 = {80 78 05 e8 75 90 01 01 80 78 06 03 75 90 01 01 80 78 0d 8b 75 90 01 01 80 78 0e d4 75 90 01 01 0f b6 50 02 90 00 } //01 00 
		$a_03_2 = {c7 44 24 04 bd ca 3b d3 89 44 24 08 8b 84 24 90 01 01 00 00 00 89 04 24 e8 90 00 } //01 00 
		$a_01_3 = {89 44 24 08 c7 44 24 04 ff ff ff ff 89 3c 24 e8 } //01 00 
		$a_01_4 = {c7 44 24 04 b8 0a 4c 53 89 44 24 08 e8 } //01 00 
		$a_01_5 = {c7 44 24 04 89 4d 39 8c 89 44 24 08 e8 } //00 00 
	condition:
		any of ($a_*)
 
}