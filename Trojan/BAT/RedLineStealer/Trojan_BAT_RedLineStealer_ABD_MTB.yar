
rule Trojan_BAT_RedLineStealer_ABD_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.ABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b 00 07 2a 90 0a 17 00 00 72 01 90 01 02 70 28 05 90 01 02 06 0a 06 28 03 90 01 02 06 0b 90 00 } //01 00 
		$a_01_1 = {42 75 66 66 65 72 65 64 53 74 72 65 61 6d } //01 00 
		$a_01_2 = {47 5a 69 70 53 74 72 65 61 6d } //01 00 
		$a_01_3 = {57 65 62 43 6c 69 65 6e 74 } //01 00 
		$a_01_4 = {67 65 74 5f 55 74 63 4e 6f 77 } //01 00 
		$a_01_5 = {54 6f 41 72 72 61 79 } //01 00 
		$a_81_6 = {33 37 2e 30 2e 31 31 2e 31 36 34 } //00 00 
	condition:
		any of ($a_*)
 
}