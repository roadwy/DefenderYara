
rule HackTool_Win64_CobaltStrike_D{
	meta:
		description = "HackTool:Win64/CobaltStrike.D,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0a 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 01 00 01 00 02 90 01 02 00 02 00 01 00 02 90 00 } //01 00 
		$a_03_1 = {69 68 69 68 69 6b 90 01 02 69 6b 69 68 69 6b 90 00 } //01 00 
		$a_03_2 = {2e 2f 2e 2f 2e 2c 90 01 02 2e 2c 2e 2f 2e 2c 90 00 } //01 00 
		$a_03_3 = {4e 4f 4e 4f 4e 4c 90 01 02 4e 4c 4e 4f 4e 4c 90 00 } //01 00 
		$a_01_4 = {4c 63 c2 4d 03 c0 42 0f 10 04 c0 48 8b c1 f3 0f 7f 01 c3 } //0a 00 
		$a_03_5 = {b9 00 00 10 00 e8 90 02 3c ba 7f 66 04 40 8b c8 48 8b 90 02 08 89 08 48 8b 4b 20 90 00 } //9c ff 
		$a_01_6 = {42 65 68 61 76 69 6f 72 3a } //9c ff  Behavior:
		$a_01_7 = {54 72 6f 6a 61 6e 3a } //9c ff  Trojan:
		$a_01_8 = {6d 70 61 74 74 72 69 62 75 74 65 } //9c ff  mpattribute
		$a_01_9 = {48 61 63 6b 54 6f 6f 6c 3a } //00 00  HackTool:
	condition:
		any of ($a_*)
 
}