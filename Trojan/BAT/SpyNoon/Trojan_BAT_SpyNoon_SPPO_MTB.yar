
rule Trojan_BAT_SpyNoon_SPPO_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SPPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_01_0 = {61 07 11 06 17 6a 58 07 8e 69 6a 5d d4 91 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_SpyNoon_SPPO_MTB_2{
	meta:
		description = "Trojan:BAT/SpyNoon.SPPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {d4 91 61 07 11 90 01 01 17 6a 58 07 8e 69 6a 5d d4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}