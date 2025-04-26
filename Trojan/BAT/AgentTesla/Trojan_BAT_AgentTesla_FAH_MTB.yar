
rule Trojan_BAT_AgentTesla_FAH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {1a 2d 48 26 08 16 07 16 1f 10 16 2c 41 26 26 26 26 26 08 16 07 1f 0f 1f 10 1a 2d 39 26 26 26 26 26 06 07 1a 2d 36 26 26 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0d 09 03 16 03 8e 69 6f ?? 00 00 0a 13 04 de 2c 0a 2b 98 0b 2b a0 0c 2b b6 28 ?? 00 00 0a 2b bd 28 ?? 00 00 0a 2b c5 6f ?? 00 00 0a 2b c5 06 07 08 09 02 03 04 28 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}