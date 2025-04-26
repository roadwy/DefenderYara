
rule Trojan_BAT_AgentTesla_PSXN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSXN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 02 11 00 11 01 28 ?? 00 00 06 13 07 20 00 00 00 00 7e 0d 02 00 04 7b d8 01 00 04 39 0f 00 00 00 26 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}