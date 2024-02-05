
rule Trojan_BAT_NjRat_NED_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 00 04 11 11 07 7b 90 01 01 00 00 04 11 11 1e d8 1e 6f 90 01 01 00 00 0a 18 28 90 01 01 00 00 0a 9c 11 11 17 d6 13 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}