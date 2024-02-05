
rule VirTool_Win64_Obfuscator_A{
	meta:
		description = "VirTool:Win64/Obfuscator.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_13_0 = {45 d1 8b 46 24 8b 4e 0c 25 00 00 00 08 eb 90 14 0b d0 8b 46 08 48 03 0b 90 00 01 } //00 1b 
		$a_48_1 = {7b 18 8b 41 3c 48 03 c1 0f b7 50 14 48 8d 74 02 18 } //0f b7 
		$a_06_2 = {48 83 ee 28 00 00 5d 04 00 00 1e 83 02 80 5c 1f 00 00 1f 83 02 80 00 00 01 00 27 00 09 00 c8 21 4c 61 71 6d 61 2e 43 00 00 01 40 05 82 5f 00 04 00 40 45 00 00 04 00 01 03 00 00 00 00 00 4a 30 00 0a c6 34 52 af 00 00 00 00 02 00 00 00 08 30 } //00 1e 
	condition:
		any of ($a_*)
 
}