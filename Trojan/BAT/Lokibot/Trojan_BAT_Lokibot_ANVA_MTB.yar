
rule Trojan_BAT_Lokibot_ANVA_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.ANVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 07 11 08 6f ?? 00 00 0a 13 09 12 09 28 ?? 00 00 0a 16 61 d2 13 0a 12 09 28 ?? 00 00 0a 16 61 d2 13 0b 12 09 28 ?? 00 00 0a 16 61 d2 13 0c 07 11 0a 6f ?? 00 00 0a 08 11 0b 6f ?? 00 00 0a 09 11 0c 6f ?? 00 00 0a 04 03 6f ?? 00 00 0a 59 13 0d 11 0d 19 32 32 07 6f ?? 00 00 0a 13 0e 08 6f ?? 00 00 0a 13 0f 09 6f ?? 00 00 0a 13 10 03 11 0e 6f ?? 00 00 0a 03 11 0f 6f ?? 00 00 0a 03 11 10 6f ?? 00 00 0a 2b 79 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}