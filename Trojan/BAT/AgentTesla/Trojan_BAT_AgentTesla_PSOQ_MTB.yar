
rule Trojan_BAT_AgentTesla_PSOQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSOQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 46 00 00 01 25 d0 1e 01 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 1f 10 8d 46 00 00 01 25 d0 1f 01 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 07 6f a4 00 00 0a 17 73 ?? ?? ?? 0a 0c 08 02 16 02 8e 69 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}