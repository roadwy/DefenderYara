
rule Trojan_BAT_SpyNoon_KAA_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 14 17 58 8c ?? ?? ?? ?? ?? ?? 00 00 0a 13 15 06 11 15 6f ?? ?? ?? ?? ?? ?? 00 00 1b 13 16 11 12 11 16 6f ?? 00 00 0a 11 14 17 58 13 14 11 14 1b 32 c8 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}