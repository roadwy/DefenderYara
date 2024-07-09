
rule Trojan_BAT_Spynoon_FUAA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.FUAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d d4 91 61 28 ?? 00 00 0a 07 11 07 08 6a 5d d4 91 28 ?? 00 00 0a 59 11 08 58 11 08 5d 28 ?? 00 00 0a 9c 00 11 05 17 6a 58 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}