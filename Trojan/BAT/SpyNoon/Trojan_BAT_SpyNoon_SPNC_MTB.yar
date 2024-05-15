
rule Trojan_BAT_SpyNoon_SPNC_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SPNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {61 07 11 0c 91 59 13 0d 11 0d 20 00 01 00 00 58 13 0e 07 11 09 11 0e 20 ff 00 00 00 5f d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}