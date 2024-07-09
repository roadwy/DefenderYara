
rule Trojan_BAT_AgentTesla_ASAA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 07 2b 61 16 13 08 2b 51 08 11 08 11 07 6f ?? 01 00 0a 13 09 16 13 0a 11 06 } //2
		$a_03_1 = {2b 1f 12 09 28 ?? 01 00 0a 13 0a 2b 14 12 09 28 ?? 01 00 0a 13 0a 2b 09 12 09 28 ?? 01 00 0a 13 0a 07 11 0a 6f ?? 01 00 0a 11 08 17 58 13 08 11 08 09 32 aa } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}