
rule HackTool_Linux_AirCrack_A_MTB{
	meta:
		description = "HackTool:Linux/AirCrack.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 69 72 63 72 61 63 6b 2d 6e 67 } //01 00  aircrack-ng
		$a_00_1 = {6c 69 62 2f 63 65 2d 77 65 70 2f 75 6e 69 71 75 65 69 76 2e 63 } //01 00  lib/ce-wep/uniqueiv.c
		$a_01_2 = {77 65 70 2d 64 65 63 6c 6f 61 6b } //01 00  wep-decloak
		$a_01_3 = {50 54 57 5f 6e 65 77 61 74 74 61 63 6b 73 74 61 74 65 28 29 } //01 00  PTW_newattackstate()
		$a_01_4 = {70 74 77 2d 64 65 62 75 67 } //01 00  ptw-debug
		$a_00_5 = {61 69 72 63 72 61 63 6b 2d 63 65 2d 77 70 61 } //00 00  aircrack-ce-wpa
	condition:
		any of ($a_*)
 
}
rule HackTool_Linux_AirCrack_A_MTB_2{
	meta:
		description = "HackTool:Linux/AirCrack.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 69 6e 69 6d 75 6d 20 72 65 71 75 69 72 65 64 20 66 6f 72 20 61 20 64 69 63 74 69 6f 6e 61 72 79 20 61 74 74 61 63 6b } //01 00  minimum required for a dictionary attack
		$a_02_1 = {70 6f 72 74 73 2f 61 69 72 63 72 61 63 6b 2d 6e 67 90 02 06 2f 61 69 72 63 72 61 63 6b 2d 6e 67 90 02 06 2f 73 72 63 2f 61 69 72 63 72 61 63 6b 2d 63 72 79 70 74 6f 90 00 } //01 00 
		$a_00_2 = {64 69 73 61 62 6c 65 20 20 62 72 75 74 65 66 6f 72 63 65 20 20 20 6d 75 6c 74 69 74 68 72 65 61 64 69 6e 67 } //01 00  disable  bruteforce   multithreading
		$a_00_3 = {50 54 57 5f 6e 65 77 61 74 74 61 63 6b 73 74 61 74 65 } //01 00  PTW_newattackstate
		$a_00_4 = {41 74 74 61 63 6b 20 77 69 6c 6c 20 62 65 20 72 65 73 74 61 72 74 65 64 20 65 76 65 72 79 20 25 64 20 63 61 70 74 75 72 65 64 20 69 76 73 } //00 00  Attack will be restarted every %d captured ivs
	condition:
		any of ($a_*)
 
}