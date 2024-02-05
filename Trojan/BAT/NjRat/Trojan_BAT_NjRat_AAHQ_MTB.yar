
rule Trojan_BAT_NjRat_AAHQ_MTB{
	meta:
		description = "Trojan:BAT/NjRat.AAHQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 72 6e d0 01 70 72 72 d0 01 70 6f 90 01 01 00 00 0a 10 00 02 6f 90 01 01 00 00 0a 18 5b 8d 90 01 01 00 00 01 0a 16 0b 38 90 01 01 00 00 00 06 07 02 07 18 5a 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 06 9c 20 04 00 00 00 38 90 01 01 00 00 00 09 3a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}