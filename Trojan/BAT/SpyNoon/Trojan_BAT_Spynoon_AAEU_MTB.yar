
rule Trojan_BAT_Spynoon_AAEU_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AAEU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 8e 69 17 da 13 11 16 13 12 2b 1b 11 04 11 12 09 11 12 9a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 12 17 d6 13 12 11 12 11 11 31 df } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}