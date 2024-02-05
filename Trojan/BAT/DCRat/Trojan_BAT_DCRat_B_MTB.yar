
rule Trojan_BAT_DCRat_B_MTB{
	meta:
		description = "Trojan:BAT/DCRat.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 00 04 07 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0d 28 90 01 01 00 00 0a 09 16 09 8e 69 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 13 04 7e 90 00 } //02 00 
		$a_03_1 = {00 00 0a 18 33 2e 09 6f 90 01 01 00 00 0a 16 6a 31 08 09 6f 90 01 01 00 00 0a 2d 02 de 26 02 09 6f 90 01 01 00 00 0a 06 7b 90 01 01 00 00 04 06 7b 90 01 01 00 00 04 16 2c 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}