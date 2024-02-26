
rule Trojan_BAT_SpyNoon_UW_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.UW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {11 04 11 05 6f 38 01 00 0a 17 73 18 01 00 0a 13 06 11 06 07 16 07 8e 69 6f 2d 01 00 0a 11 06 6f 2e 01 00 0a 11 04 6f 29 01 00 0a 28 39 01 00 0a 2a } //00 00 
	condition:
		any of ($a_*)
 
}