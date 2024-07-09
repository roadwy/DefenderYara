
rule Trojan_BAT_Spynoon_ASAT_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.ASAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 0a 74 ?? 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 74 ?? 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f ?? 00 00 0a 26 16 13 0e 38 ?? fe ff ff 11 09 17 58 13 09 1d 13 0e 38 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}