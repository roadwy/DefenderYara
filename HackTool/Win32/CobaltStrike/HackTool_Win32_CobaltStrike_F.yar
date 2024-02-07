
rule HackTool_Win32_CobaltStrike_F{
	meta:
		description = "HackTool:Win32/CobaltStrike.F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 09 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 6a 0d 8b c1 5b f7 f3 8a 44 90 01 01 08 30 90 01 01 41 90 00 } //01 00 
		$a_01_1 = {8b 3b 89 c8 31 d2 01 cf 41 89 7d e0 bf 0d 00 00 00 f7 f7 8a 44 13 08 8b 55 e0 30 02 } //01 00 
		$a_01_2 = {8b 45 08 89 cf bb 0d 00 00 00 31 d2 03 38 89 c8 41 f7 f3 8b 45 08 8a 44 10 08 8a 44 10 08 30 07 } //9c ff 
		$a_01_3 = {42 65 68 61 76 69 6f 72 3a } //9c ff  Behavior:
		$a_01_4 = {54 72 6f 6a 61 6e 3a } //9c ff  Trojan:
		$a_01_5 = {6d 70 61 74 74 72 69 62 75 74 65 } //9c ff  mpattribute
		$a_01_6 = {48 61 63 6b 54 6f 6f 6c 3a } //9c ff  HackTool:
		$a_01_7 = {7f 00 00 18 00 00 00 00 00 00 00 ff ff ff ff } //9c ff 
		$a_01_8 = {f7 7f 00 00 2a 00 00 00 00 00 00 00 ff ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}