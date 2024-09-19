
rule Trojan_BAT_SpyNoon_AMAX_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.AMAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 5d 08 58 08 5d 13 [0-28] 61 [0-0f] 59 20 00 02 00 00 58 [0-0f] 20 00 01 00 00 5d 20 00 04 00 00 58 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}