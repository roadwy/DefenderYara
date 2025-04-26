
rule Trojan_BAT_AgentTesla_PSYX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSYX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 75 1e 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 13 0c 20 00 00 00 00 7e 2d 02 00 04 7b 3a 02 00 04 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}