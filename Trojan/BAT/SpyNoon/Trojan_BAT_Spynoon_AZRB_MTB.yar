
rule Trojan_BAT_Spynoon_AZRB_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AZRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 07 11 08 6f ?? 00 00 06 13 0f 12 0f 28 ?? 00 00 0a 13 10 12 0f 28 ?? 00 00 0a 13 11 02 11 10 11 11 6f ?? 00 00 0a 13 12 07 11 12 6f ?? 00 00 06 13 12 08 17 6f ?? 00 00 06 00 12 12 28 ?? 00 00 0a 13 0b 11 0b 28 ?? 00 00 06 00 28 ?? 00 00 06 13 0b 11 0b 18 62 11 0b 1c 63 60 d2 13 0b 11 0b 18 63 11 0b 1c 62 60 d2 13 0b } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}