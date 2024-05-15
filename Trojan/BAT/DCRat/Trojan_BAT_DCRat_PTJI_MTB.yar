
rule Trojan_BAT_DCRat_PTJI_MTB{
	meta:
		description = "Trojan:BAT/DCRat.PTJI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {2d 18 06 02 28 90 01 01 00 00 06 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 06 28 90 01 01 00 00 0a 26 02 28 90 01 01 00 00 0a 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}