
rule Trojan_BAT_SpyNoon_KAD_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 5d d4 91 08 11 ?? 69 1f ?? 5d 6f ?? 00 00 0a 61 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}