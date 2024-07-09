
rule Trojan_BAT_AgentTesla_ASAS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 1e 11 18 11 1a 58 11 19 11 1b 58 6f ?? 00 00 0a 13 59 12 59 28 ?? 00 00 0a 13 22 11 1d 11 1c 11 22 9c 11 1c 17 58 13 1c 11 1b 17 58 13 1b 11 1b 17 fe 04 13 23 11 23 2d c6 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}