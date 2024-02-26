
rule Trojan_BAT_DCRat_NL_MTB{
	meta:
		description = "Trojan:BAT/DCRat.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e b6 08 90 01 02 0e 06 17 59 95 58 0e 05 90 00 } //05 00 
		$a_03_1 = {03 02 4b 03 05 5f 04 05 66 5f 60 58 0e 07 0e 04 95 58 7e b6 90 01 03 0e 06 17 59 95 58 0e 05 90 01 02 0d 00 06 58 54 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}