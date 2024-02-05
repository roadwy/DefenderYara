
rule Trojan_BAT_SpyNoon_MR_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {13 1f 00 d0 90 02 04 28 90 02 04 72 90 02 04 18 1b 8d 90 02 04 25 16 72 90 02 04 a2 25 17 20 90 02 04 8c 90 02 04 a2 25 1a 17 8d 90 02 04 25 16 03 74 90 02 04 28 90 02 04 a2 a2 28 90 02 04 74 90 02 04 13 20 02 11 20 72 90 02 04 6f 90 02 04 7d 90 02 04 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}