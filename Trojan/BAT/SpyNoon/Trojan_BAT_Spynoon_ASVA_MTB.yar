
rule Trojan_BAT_Spynoon_ASVA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.ASVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 0a 11 0b 6f ?? 00 00 0a 13 0c 12 0c 28 ?? 00 00 0a 16 61 d2 13 0d 12 0c 28 ?? 00 00 0a 16 61 d2 13 0e 12 0c 28 ?? 00 00 0a 16 61 d2 13 0f 07 11 0d 6f ?? 00 00 0a 00 08 11 0e 6f ?? 00 00 0a 00 09 11 0f 6f ?? 00 00 0a 00 04 03 6f ?? 00 00 0a 59 13 10 11 10 19 fe 04 16 fe 01 13 11 11 11 2c 3a 00 07 6f ?? 00 00 0a 13 12 08 6f ?? 00 00 0a 13 13 09 6f ?? 00 00 0a 13 14 03 11 12 6f ?? 00 00 0a 00 03 11 13 6f ?? 00 00 0a 00 03 11 14 6f ?? 00 00 0a 00 00 38 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}