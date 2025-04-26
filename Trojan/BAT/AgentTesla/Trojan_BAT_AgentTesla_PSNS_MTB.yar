
rule Trojan_BAT_AgentTesla_PSNS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 7e 03 00 00 04 6f 35 00 00 0a 02 16 02 8e 69 6f 36 00 00 0a 0a 2b 00 06 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}