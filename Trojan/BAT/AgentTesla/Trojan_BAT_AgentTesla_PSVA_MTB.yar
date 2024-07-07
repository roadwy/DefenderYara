
rule Trojan_BAT_AgentTesla_PSVA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 00 11 00 28 90 01 01 00 00 06 11 00 28 90 01 01 00 00 06 28 90 01 01 00 00 06 13 01 20 02 00 00 00 38 9f ff ff ff 11 00 02 7b 04 00 00 04 28 90 01 01 00 00 06 28 90 01 01 00 00 06 28 14 00 00 06 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}