
rule HackTool_AndroidOS_WifiCrack_B_MTB{
	meta:
		description = "HackTool:AndroidOS/WifiCrack.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {42 72 75 74 65 66 6f 72 63 65 43 6f 6e 66 69 67 41 63 74 69 76 69 74 79 } //01 00  BruteforceConfigActivity
		$a_00_1 = {50 61 73 73 77 6f 72 64 54 65 73 74 65 72 } //01 00  PasswordTester
		$a_00_2 = {77 69 62 72 2d 64 61 74 61 2e 64 61 74 } //01 00  wibr-data.dat
		$a_00_3 = {62 72 75 74 65 66 6f 72 63 65 47 65 6e 65 72 61 74 6f 72 } //01 00  bruteforceGenerator
		$a_00_4 = {4c 63 7a 2f 61 75 72 61 64 65 73 69 67 6e 2f 77 69 62 72 70 6c 75 73 2f 4d 6f 6e 69 74 6f 72 41 63 74 69 76 69 74 79 } //01 00  Lcz/auradesign/wibrplus/MonitorActivity
		$a_00_5 = {67 65 74 54 6f 74 61 6c 50 61 73 73 77 6f 72 64 73 } //01 00  getTotalPasswords
		$a_00_6 = {71 75 65 75 65 50 61 73 73 77 6f 72 64 50 72 6f 67 72 65 73 73 } //00 00  queuePasswordProgress
		$a_00_7 = {5d 04 00 00 63 c8 } //04 80 
	condition:
		any of ($a_*)
 
}