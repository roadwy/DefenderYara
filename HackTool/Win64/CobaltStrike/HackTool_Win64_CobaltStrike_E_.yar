
rule HackTool_Win64_CobaltStrike_E_{
	meta:
		description = "HackTool:Win64/CobaltStrike.E!!CobaltStrike.E64,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {eb 27 5b 8b 2b 83 c3 04 8b 13 31 ea 83 c3 04 53 8b 33 31 ee 89 33 31 f5 83 c3 04 83 ea 04 31 f6 39 f2 } //01 00 
		$a_01_1 = {eb 33 5d 8b 45 00 48 83 c5 04 8b 4d 00 31 c1 48 83 c5 04 55 8b 55 00 31 c2 89 55 00 31 d0 48 83 c5 04 83 e9 04 31 d2 39 d1 } //9c ff 
		$a_01_2 = {42 65 68 61 76 69 6f 72 3a } //9c ff 
		$a_01_3 = {54 72 6f 6a 61 6e 3a } //9c ff 
		$a_01_4 = {6d 70 61 74 74 72 69 62 75 74 65 } //9c ff 
		$a_01_5 = {48 61 63 6b 54 6f 6f 6c 3a } //05 00 
	condition:
		any of ($a_*)
 
}