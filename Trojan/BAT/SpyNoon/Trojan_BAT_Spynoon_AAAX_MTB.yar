
rule Trojan_BAT_Spynoon_AAAX_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AAAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 03 28 01 00 00 2b 28 90 01 01 00 00 2b 13 03 20 90 01 01 00 00 00 38 90 01 01 ff ff ff d0 90 01 01 00 00 01 28 90 01 01 00 00 0a 11 04 28 90 01 01 00 00 06 28 90 01 01 00 00 2b 72 90 01 01 00 00 70 28 90 01 01 00 00 0a 02 7b 90 01 01 00 00 04 6f 90 01 01 00 00 0a 28 90 01 01 00 00 06 26 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}