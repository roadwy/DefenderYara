
rule Trojan_BAT_DCRat_C_MTB{
	meta:
		description = "Trojan:BAT/DCRat.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 00 06 0b 07 28 04 00 00 0a 20 90 01 01 00 00 00 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 7d 90 01 01 00 00 04 07 fe 90 00 } //02 00 
		$a_03_1 = {00 00 0a 20 00 00 00 00 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0a 06 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}