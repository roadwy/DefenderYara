
rule Trojan_BAT_DCRat_K_MTB{
	meta:
		description = "Trojan:BAT/DCRat.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {07 02 12 02 12 03 6f 90 01 01 00 00 0a 09 8e 69 20 90 01 04 20 90 01 04 28 90 01 01 00 00 06 59 8d 90 01 01 00 00 01 13 04 09 20 90 01 04 20 90 01 04 28 90 01 01 00 00 06 11 04 20 90 01 04 20 90 01 04 28 90 01 01 00 00 06 11 04 8e 69 28 90 01 01 00 00 0a 11 04 13 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}