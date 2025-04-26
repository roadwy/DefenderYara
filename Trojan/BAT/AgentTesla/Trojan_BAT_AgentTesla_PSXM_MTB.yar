
rule Trojan_BAT_AgentTesla_PSXM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 15 00 00 06 11 07 28 ?? 00 00 06 28 ?? 00 00 06 20 00 00 00 00 7e df 01 00 04 7b 24 02 00 04 3a c9 ff ff ff 26 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}