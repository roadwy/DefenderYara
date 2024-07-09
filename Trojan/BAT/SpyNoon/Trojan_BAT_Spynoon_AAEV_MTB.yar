
rule Trojan_BAT_Spynoon_AAEV_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AAEV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 07 2b 24 00 09 11 07 18 6f ?? 00 00 0a 13 08 11 04 11 07 18 5b 11 08 1f 10 28 ?? 00 00 0a d2 9c 00 11 07 18 58 13 07 11 07 20 02 d0 00 00 fe 04 13 09 11 09 2d cd } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}