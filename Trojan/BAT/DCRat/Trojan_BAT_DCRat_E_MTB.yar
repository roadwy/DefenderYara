
rule Trojan_BAT_DCRat_E_MTB{
	meta:
		description = "Trojan:BAT/DCRat.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {ff 11 03 7e 90 01 02 00 04 28 90 01 02 00 06 73 90 01 01 00 00 0a 20 20 02 00 00 7e 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}