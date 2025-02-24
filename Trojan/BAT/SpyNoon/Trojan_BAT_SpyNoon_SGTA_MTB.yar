
rule Trojan_BAT_SpyNoon_SGTA_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SGTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 16 12 00 28 ?? 00 00 0a 9c 25 17 12 00 28 ?? 00 00 0a 9c 25 18 12 00 28 ?? 00 00 0a 9c 07 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}