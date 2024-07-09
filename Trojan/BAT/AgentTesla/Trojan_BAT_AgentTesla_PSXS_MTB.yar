
rule Trojan_BAT_AgentTesla_PSXS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSXS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 b4 4b 00 00 28 ?? 00 00 06 28 ?? 00 00 06 13 01 20 00 00 00 00 7e 10 02 00 04 7b 27 02 00 04 3a bd ff ff ff } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}