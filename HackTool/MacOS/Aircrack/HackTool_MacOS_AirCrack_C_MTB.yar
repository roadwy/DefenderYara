
rule HackTool_MacOS_AirCrack_C_MTB{
	meta:
		description = "HackTool:MacOS/AirCrack.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 69 72 63 72 61 63 6b 2d 6e 67 } //01 00  Aircrack-ng
		$a_00_1 = {77 77 77 2e 61 69 72 63 72 61 63 6b 2d 6e 67 2e 6f 72 67 } //01 00  www.aircrack-ng.org
		$a_00_2 = {74 72 79 20 74 68 65 20 65 78 70 65 72 69 6d 65 6e 74 61 6c 20 62 72 75 74 65 66 6f 72 63 65 20 61 74 74 61 63 6b 73 } //01 00  try the experimental bruteforce attacks
		$a_00_3 = {50 54 57 5f 6e 65 77 61 74 74 61 63 6b 73 74 61 74 65 } //01 00  PTW_newattackstate
		$a_00_4 = {51 75 69 74 74 69 6e 67 20 61 69 72 63 72 61 63 6b 2d 6e 67 } //01 00  Quitting aircrack-ng
		$a_00_5 = {41 74 74 61 63 6b 20 66 61 69 6c 65 64 2e 20 50 6f 73 73 69 62 6c 65 20 72 65 61 73 6f 6e 73 3a } //00 00  Attack failed. Possible reasons:
		$a_00_6 = {5d 04 00 00 } //d6 08 
	condition:
		any of ($a_*)
 
}