
rule Trojan_BAT_SpyNoon_SPCC_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SPCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 91 13 09 08 11 07 91 13 0a 07 11 06 91 11 0a 61 13 0b } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}