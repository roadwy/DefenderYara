
rule VirTool_Win64_BruterShell_A{
	meta:
		description = "VirTool:Win64/BruterShell.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 c9 ba 26 25 19 3e 49 89 c0 e8 90 01 04 44 8d 43 01 90 00 } //01 00 
		$a_03_1 = {41 80 f8 4c 90 02 10 80 79 01 8b 75 90 01 01 80 79 02 d1 75 90 01 01 41 80 f9 b8 75 90 01 01 80 79 06 00 90 00 } //01 00 
		$a_03_2 = {4c 8b 03 ba bd ca 3b d3 48 89 d9 48 89 84 24 90 01 01 00 00 00 e8 90 00 } //01 00 
		$a_03_3 = {48 c7 c2 ff ff ff ff c7 44 24 90 01 01 04 00 00 00 c7 44 24 90 01 01 00 30 00 00 90 02 10 e8 90 00 } //01 00 
		$a_01_4 = {ba b8 0a 4c 53 e8 } //01 00 
		$a_03_5 = {ba 89 4d 39 8c 48 89 84 24 90 01 02 00 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win64_BruterShell_A_2{
	meta:
		description = "VirTool:Win64/BruterShell.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 80 f8 4c 90 02 10 80 79 01 8b 75 90 01 01 80 79 02 d1 75 90 01 01 41 80 f9 b8 75 90 01 01 80 79 06 00 90 00 } //01 00 
		$a_03_1 = {48 c7 c2 ff ff ff ff c7 44 24 90 01 01 04 00 00 00 c7 44 24 90 01 01 00 30 00 00 90 02 10 e8 90 00 } //01 00 
		$a_01_2 = {ba b8 0a 4c 53 e8 } //01 00 
		$a_03_3 = {ba 89 4d 39 8c 48 89 84 24 90 01 02 00 00 e8 90 00 } //01 00 
		$a_03_4 = {ba 29 44 e8 57 90 02 10 e8 90 02 10 ba 0e e8 4b 1e 90 02 10 e8 90 00 } //01 00 
		$a_03_5 = {48 b8 3a 7b 22 61 75 74 68 22 90 02 20 c7 84 24 90 01 02 00 00 50 4f 53 54 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}