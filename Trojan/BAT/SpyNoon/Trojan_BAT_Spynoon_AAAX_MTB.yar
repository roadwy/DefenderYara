
rule Trojan_BAT_Spynoon_AAAX_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AAAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 03 28 01 00 00 2b 28 ?? 00 00 2b 13 03 20 ?? 00 00 00 38 ?? ff ff ff d0 ?? 00 00 01 28 ?? 00 00 0a 11 04 28 ?? 00 00 06 28 ?? 00 00 2b 72 ?? 00 00 70 28 ?? 00 00 0a 02 7b ?? 00 00 04 6f ?? 00 00 0a 28 ?? 00 00 06 26 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}