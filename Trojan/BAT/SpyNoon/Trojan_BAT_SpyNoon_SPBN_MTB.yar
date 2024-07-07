
rule Trojan_BAT_SpyNoon_SPBN_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SPBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 5d 91 28 90 01 03 0a 59 20 00 01 00 00 58 13 90 01 01 08 11 90 01 01 11 90 01 01 20 00 01 00 00 5d d2 9c 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}