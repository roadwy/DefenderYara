
rule Trojan_BAT_zgRAT_L_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {09 11 04 08 11 04 91 20 90 01 02 00 00 28 90 01 02 00 06 11 04 20 90 01 02 00 00 28 90 01 02 00 06 28 90 01 02 00 0a 5d 28 90 01 02 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 08 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_zgRAT_L_MTB_2{
	meta:
		description = "Trojan:BAT/zgRAT.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {91 61 d2 9c 90 09 0e 00 02 11 90 01 01 02 11 90 01 01 91 03 11 90 01 01 03 8e 69 5d 90 00 } //02 00 
		$a_03_1 = {16 1f 20 9d 11 90 01 01 6f 90 01 01 00 00 0a 13 90 01 01 20 90 09 0d 00 02 16 9a 17 8d 90 01 01 00 00 01 13 90 01 01 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}