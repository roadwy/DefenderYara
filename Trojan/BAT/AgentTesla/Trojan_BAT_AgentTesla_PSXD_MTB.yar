
rule Trojan_BAT_AgentTesla_PSXD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 3c 45 00 00 28 ?? 0a 00 06 28 ?? 00 00 0a 20 d4 45 00 00 28 ?? 0a 00 06 28 ?? 00 00 0a 6f 04 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}