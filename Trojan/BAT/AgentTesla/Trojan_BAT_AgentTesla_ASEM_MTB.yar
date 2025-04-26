
rule Trojan_BAT_AgentTesla_ASEM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 06 6f ?? 02 00 0a 06 6f ?? 02 00 0a 6f ?? 02 00 0a 13 04 73 ?? 00 00 0a 0b 28 ?? 0c 00 06 75 ?? 00 00 1b 73 ?? 01 00 0a 0c 08 11 04 16 73 ?? 02 00 0a 0d 09 07 6f ?? 02 00 0a 07 6f ?? 01 00 0a 13 05 de } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}