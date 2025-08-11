
rule Trojan_BAT_Stealer_ARVA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.ARVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 02 7b ?? 00 00 04 6f ?? 00 00 0a 08 02 7b ?? 00 00 04 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 2b 24 2b 26 16 2b 26 8e 69 2b 25 2b 2a 2b 2c 2b 31 2b 33 2b 38 11 06 72 ?? ?? 00 70 03 28 ?? 00 00 06 17 0b de 5c 11 05 2b d8 06 2b d7 06 2b d7 6f ?? 00 00 0a 2b d4 11 05 2b d2 6f ?? 00 00 0a 2b cd 11 04 2b cb 6f ?? 00 00 0a 2b c6 13 06 2b c4 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}