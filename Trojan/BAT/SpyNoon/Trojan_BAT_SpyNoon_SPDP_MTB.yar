
rule Trojan_BAT_SpyNoon_SPDP_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SPDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 5d d4 91 28 90 01 03 0a 59 11 07 58 11 07 5d 28 90 01 03 0a 9c 11 04 17 6a 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}