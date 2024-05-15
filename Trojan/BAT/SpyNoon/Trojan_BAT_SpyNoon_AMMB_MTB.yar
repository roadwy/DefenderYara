
rule Trojan_BAT_SpyNoon_AMMB_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.AMMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {5d 91 61 13 90 02 0f 07 09 17 58 08 5d 91 59 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_SpyNoon_AMMB_MTB_2{
	meta:
		description = "Trojan:BAT/SpyNoon.AMMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {5d 91 61 6a 07 11 90 01 01 17 6a 58 07 8e 69 6a 5d d4 91 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}