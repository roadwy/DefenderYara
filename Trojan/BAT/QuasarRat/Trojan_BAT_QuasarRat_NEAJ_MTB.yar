
rule Trojan_BAT_QuasarRat_NEAJ_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.NEAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {33 30 36 32 35 31 65 35 2d 39 30 37 34 2d 34 63 65 33 2d 62 65 30 37 2d 66 33 64 35 36 64 61 62 34 63 61 33 } //01 00 
		$a_01_1 = {67 65 74 5f 44 57 53 32 33 } //01 00 
		$a_01_2 = {57 69 6e 46 6f 72 6d 73 41 70 70 31 } //01 00 
		$a_01_3 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}