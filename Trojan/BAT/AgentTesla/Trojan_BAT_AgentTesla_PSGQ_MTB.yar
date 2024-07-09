
rule Trojan_BAT_AgentTesla_PSGQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSGQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 00 0c 00 00 28 16 00 00 0a 7e 05 00 00 04 72 03 00 00 70 6f 17 00 00 0a 80 ?? ?? ?? 04 16 0a 2b 19 7e ?? ?? ?? 04 06 7e ?? ?? ?? 04 06 91 20 34 03 00 00 59 d2 9c 06 17 58 0a 06 7e ?? ?? ?? 04 8e 69 32 dd 7e ?? ?? ?? 04 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}