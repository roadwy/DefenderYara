
rule Trojan_BAT_AgentTesla_PSYK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSYK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {61 38 27 fe ff ff 28 90 01 01 00 00 0a 7e 01 00 00 04 02 08 6f 2a 00 00 0a 28 90 01 01 00 00 0a a5 01 00 00 1b 0b 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}