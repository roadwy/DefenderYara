
rule Trojan_BAT_NanocoreRat_CXRO_MTB{
	meta:
		description = "Trojan:BAT/NanocoreRat.CXRO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 6c 75 62 74 78 65 78 6d 6b 71 6a 78 6f 6c } //01 00 
		$a_01_1 = {7a 36 6f 47 64 41 31 34 63 4f 78 52 6e 4e 5a 75 32 4d } //01 00 
		$a_01_2 = {54 79 37 61 63 58 73 71 6b 4c 4f 6e 51 51 39 31 69 75 } //01 00 
		$a_01_3 = {47 39 32 37 56 5a 46 4c 64 4e 32 36 35 44 33 4d 73 54 } //01 00 
		$a_01_4 = {4f 6c 52 52 71 42 53 4f 66 76 77 77 65 55 63 4c 63 64 } //00 00 
	condition:
		any of ($a_*)
 
}