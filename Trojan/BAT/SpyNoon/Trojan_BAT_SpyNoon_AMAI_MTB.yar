
rule Trojan_BAT_SpyNoon_AMAI_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.AMAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 08 18 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 02 8e 69 8d ?? 00 00 01 13 04 02 73 ?? 00 00 0a 13 05 11 05 09 16 73 ?? 00 00 0a 13 06 11 06 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 07 12 04 11 07 28 ?? 00 00 2b de 18 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}