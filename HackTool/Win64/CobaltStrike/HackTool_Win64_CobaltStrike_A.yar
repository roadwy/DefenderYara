
rule HackTool_Win64_CobaltStrike_A{
	meta:
		description = "HackTool:Win64/CobaltStrike.A,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 00 01 00 02 90 01 02 00 02 00 01 00 02 90 00 } //01 00 
		$a_03_1 = {69 68 69 68 69 6b 90 01 02 69 6b 69 68 69 6b 90 00 } //01 00 
		$a_03_2 = {2e 2f 2e 2f 2e 2c 90 01 02 2e 2c 2e 2f 2e 2c 90 00 } //01 00 
		$a_03_3 = {4e 4f 4e 4f 4e 4c 90 01 02 4e 4c 4e 4f 4e 4c 90 00 } //01 00 
		$a_01_4 = {4c 63 c2 4d 03 c0 42 0f 10 04 c0 48 8b c1 f3 0f 7f 01 c3 } //0a 00 
		$a_03_5 = {48 ff c0 48 3d 00 10 00 00 7c f1 90 09 04 00 80 90 01 02 90 17 03 01 01 01 2e 69 4e 48 90 00 } //0a 00 
		$a_01_6 = {0f af d1 44 8b c8 b8 1f 85 eb 51 f7 e2 41 8b c1 44 8b c2 33 d2 41 c1 e8 05 41 f7 f0 } //0a 00 
		$a_03_7 = {b9 00 00 10 00 e8 90 02 3c ba 7f 66 04 40 8b c8 48 8b 90 02 08 89 08 48 8b 4b 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}