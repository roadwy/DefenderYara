
rule Trojan_BAT_Lokibot_ZDAA_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.ZDAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 06 07 6f ?? 00 00 0a 1d 62 06 07 17 58 6f ?? 00 00 0a 1c 62 58 06 07 18 58 6f ?? 00 00 0a 1b 62 58 06 07 19 58 6f ?? 00 00 0a 1a 62 58 06 07 1a 58 6f ?? 00 00 0a 19 62 58 06 07 1b 58 6f ?? 00 00 0a 18 62 58 06 07 1c 58 6f ?? 00 00 0a 17 62 58 06 07 1d 58 6f ?? 00 00 0a 58 d2 6f ?? 00 00 0a 07 1e 58 0b 07 06 6f ?? 00 00 0a fe 04 13 08 11 08 2d 8a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}