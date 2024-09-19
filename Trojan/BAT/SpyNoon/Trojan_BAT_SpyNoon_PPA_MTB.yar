
rule Trojan_BAT_SpyNoon_PPA_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.PPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 09 11 04 28 ?? ?? ?? 06 13 05 02 11 04 08 28 ?? ?? ?? 06 13 06 02 07 11 06 08 28 ?? ?? ?? 06 13 07 02 07 11 04 08 11 05 11 07 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}