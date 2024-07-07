
rule Trojan_BAT_SpyNoon_SPBP_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SPBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {d4 91 61 07 11 0e 11 0c 6a 5d d4 91 28 90 01 03 0a 59 11 0f 58 11 0f 5d 28 90 01 03 0a 9c 00 11 0b 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}