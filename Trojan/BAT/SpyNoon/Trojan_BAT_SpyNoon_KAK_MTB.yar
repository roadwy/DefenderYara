
rule Trojan_BAT_SpyNoon_KAK_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.KAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 5d 08 58 ?? ?? ?? ?? 08 5d [0-14] 61 ?? ?? ?? ?? 20 00 04 00 00 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}