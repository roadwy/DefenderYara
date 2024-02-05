
rule Trojan_BAT_DcRat_NEAA_MTB{
	meta:
		description = "Trojan:BAT/DcRat.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {12 02 28 25 01 00 0a 0d 02 12 03 28 27 01 00 0a 12 03 28 26 01 00 0a 6f c5 00 00 0a 10 00 12 02 28 28 01 00 0a 3a d6 ff ff ff } //05 00 
		$a_01_1 = {72 38 6c 39 73 4a 4c 70 73 4b 78 4b 62 47 31 32 31 5a 65 } //05 00 
		$a_01_2 = {70 44 41 64 42 33 6c 33 77 41 33 58 75 67 57 46 4e 64 71 } //00 00 
	condition:
		any of ($a_*)
 
}