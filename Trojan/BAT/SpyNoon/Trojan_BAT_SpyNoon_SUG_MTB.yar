
rule Trojan_BAT_SpyNoon_SUG_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SUG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {07 09 91 11 06 61 13 07 07 09 11 07 11 05 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}