
rule Trojan_BAT_SpyNoon_SPBN_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SPBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 13 ?? 08 11 ?? 11 ?? 20 00 01 00 00 5d d2 9c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}