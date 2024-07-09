
rule Trojan_BAT_SpyNoon_SPZZ_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SPZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 03 00 00 04 6f ?? ?? ?? 0a 0e 04 0e 09 02 8e 69 6f ?? ?? ?? 0a 0a 06 0b 2b 00 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}