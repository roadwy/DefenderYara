
rule Trojan_BAT_AgentTesla_AMAO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 14 fe ?? ?? 00 00 06 73 ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 06 75 ?? 00 00 1b 73 ?? 00 00 0a 0d 09 07 16 73 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 7e ?? 00 00 04 08 6f ?? 00 00 0a 14 6f ?? 00 00 0a dd } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}