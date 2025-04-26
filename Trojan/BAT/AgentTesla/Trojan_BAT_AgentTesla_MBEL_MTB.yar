
rule Trojan_BAT_AgentTesla_MBEL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 6f 08 11 0a 11 09 6f ?? 00 00 0a 13 0b 16 13 0c 11 05 11 08 9a 72 b3 02 00 70 28 ?? 00 00 0a 2c 0b 12 0b 28 ?? 00 00 0a 13 0c 2b 36 11 05 11 08 9a 72 b7 02 00 70 28 ?? 00 00 0a 2c 0b 12 0b 28 ?? 00 00 0a 13 0c 2b 1a 11 05 11 08 9a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}