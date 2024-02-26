
rule Trojan_BAT_zgRAT_K_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {09 11 05 08 11 05 91 11 04 11 05 11 04 6f 90 01 02 00 0a 5d 6f 90 01 02 00 0a 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}