
rule Trojan_BAT_AgentTesla_PSYS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSYS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 09 16 a3 01 00 00 1b 0b 11 07 20 4f e1 4e d0 5a 20 f8 29 3a 76 61 38 2e ff ff ff 28 ?? 00 00 0a 7e 01 00 00 04 02 08 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}