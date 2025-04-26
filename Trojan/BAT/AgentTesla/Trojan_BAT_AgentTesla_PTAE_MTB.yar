
rule Trojan_BAT_AgentTesla_PTAE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 74 0f 00 00 01 13 04 16 0b 2b 26 11 04 07 16 6f ?? 00 00 0a 13 08 12 08 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}