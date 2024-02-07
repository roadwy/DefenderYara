
rule Trojan_BAT_DiamndFox_PA_MTB{
	meta:
		description = "Trojan:BAT/DiamndFox.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 04 00 "
		
	strings :
		$a_01_0 = {61 00 48 00 52 00 30 00 63 00 44 00 6f 00 76 00 4c 00 7a 00 4d 00 33 00 4c 00 6a 00 45 00 79 00 4d 00 43 00 34 00 79 00 4d 00 6a 00 49 00 75 00 4d 00 6a 00 51 00 78 00 4c 00 32 00 5a 00 7a 00 4c 00 33 00 64 00 68 00 62 00 47 00 78 00 77 00 59 00 58 00 42 00 6c 00 63 00 69 00 35 00 71 00 63 00 47 00 56 00 6e 00 } //01 00  aHR0cDovLzM3LjEyMC4yMjIuMjQxL2ZzL3dhbGxwYXBlci5qcGVn
		$a_01_1 = {64 00 65 00 63 00 62 00 79 00 74 00 65 00 63 00 } //01 00  decbytec
		$a_01_2 = {72 00 75 00 6e 00 6e 00 65 00 72 00 } //01 00  runner
		$a_01_3 = {5c 00 77 00 61 00 6c 00 6c 00 70 00 61 00 70 00 65 00 72 00 2e 00 6a 00 70 00 65 00 67 00 } //01 00  \wallpaper.jpeg
		$a_01_4 = {5c 49 4d 47 2e 70 64 62 } //00 00  \IMG.pdb
		$a_00_5 = {5d 04 00 00 a3 6f } //04 80 
	condition:
		any of ($a_*)
 
}