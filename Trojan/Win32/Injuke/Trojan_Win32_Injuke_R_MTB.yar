
rule Trojan_Win32_Injuke_R_MTB{
	meta:
		description = "Trojan:Win32/Injuke.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 00 6f 00 6f 00 6e 00 66 00 65 00 6c 00 6c 00 6f 00 77 00 20 00 67 00 65 00 6f 00 6d 00 61 00 6e 00 63 00 69 00 65 00 73 00 } //01 00  boonfellow geomancies
		$a_01_1 = {66 00 69 00 72 00 65 00 66 00 6c 00 79 00 20 00 36 00 35 00 30 00 } //01 00  firefly 650
		$a_01_2 = {6d 00 69 00 73 00 68 00 65 00 61 00 72 00 69 00 6e 00 67 00 } //01 00  mishearing
		$a_01_3 = {71 00 75 00 69 00 74 00 65 00 76 00 65 00 } //01 00  quiteve
		$a_01_4 = {66 00 69 00 72 00 65 00 62 00 65 00 64 00 } //01 00  firebed
		$a_01_5 = {62 00 6f 00 6f 00 6e 00 64 00 6f 00 67 00 67 00 6c 00 69 00 6e 00 67 00 } //00 00  boondoggling
	condition:
		any of ($a_*)
 
}