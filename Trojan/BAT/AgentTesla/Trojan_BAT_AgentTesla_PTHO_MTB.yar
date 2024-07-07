
rule Trojan_BAT_AgentTesla_PTHO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTHO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 d6 e0 ff ff 28 90 01 01 00 00 06 11 0e 16 11 0e 8e 69 28 90 01 01 00 00 06 13 05 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}