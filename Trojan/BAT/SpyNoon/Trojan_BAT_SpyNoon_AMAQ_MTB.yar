
rule Trojan_BAT_SpyNoon_AMAQ_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.AMAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 58 08 5d 13 [0-19] 61 [0-0f] 17 58 08 58 08 5d [0-1e] 08 58 08 5d 13 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}