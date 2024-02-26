
rule Trojan_BAT_DCRat_PTFC_MTB{
	meta:
		description = "Trojan:BAT/DCRat.PTFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {08 8d 3a 00 00 01 13 04 7e 99 08 00 04 02 1a 58 11 04 16 08 28 90 01 01 01 00 0a 28 90 01 01 01 00 0a 11 04 16 11 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}