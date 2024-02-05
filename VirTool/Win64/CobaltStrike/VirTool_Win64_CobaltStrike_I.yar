
rule VirTool_Win64_CobaltStrike_I{
	meta:
		description = "VirTool:Win64/CobaltStrike.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 60 ea 00 00 ff d3 eb f7 90 02 10 48 ff e1 90 00 } //01 00 
		$a_03_1 = {41 b8 00 30 00 00 31 c9 48 89 f7 ff 15 90 01 04 48 89 c3 31 c0 39 f8 7d 90 01 01 48 89 c2 83 e2 03 90 00 } //01 00 
		$a_03_2 = {4c 8d 4c 24 3c 48 89 f2 48 89 d9 41 b8 20 00 00 00 ff 15 90 01 04 4c 8d 90 01 02 ff ff ff 49 89 d9 31 d2 31 c9 48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 ff 15 90 01 04 90 90 48 83 c4 40 90 00 } //00 00 
		$a_00_3 = {78 ad } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win64_CobaltStrike_I_2{
	meta:
		description = "VirTool:Win64/CobaltStrike.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b 04 37 44 8b f7 8b c8 48 89 44 24 50 ff 15 90 01 04 8b 4c 24 54 44 8b f8 ff 15 90 01 04 03 f8 8b cf 48 83 c1 08 48 3b cb 77 26 48 8d 56 08 44 8b c0 41 8b cf 49 03 d6 e8 90 01 04 83 c7 08 3b fb 72 b9 90 00 } //01 00 
		$a_03_1 = {73 79 73 6e 61 74 69 76 65 90 02 08 2c 90 02 08 25 73 20 28 61 64 6d 69 6e 29 90 02 08 48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 90 00 } //01 00 
		$a_01_2 = {44 09 30 09 25 30 32 64 2f 25 30 32 64 2f 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 09 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}