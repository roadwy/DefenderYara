
rule Trojan_BAT_SpyNoon_MBZR_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.MBZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {91 61 08 11 07 17 58 20 00 dc 00 00 5d 91 09 58 09 5d 59 d2 } //00 00 
	condition:
		any of ($a_*)
 
}