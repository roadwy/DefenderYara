
rule Trojan_BAT_AgentTesla_LJE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LJE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {19 62 d2 58 86 11 07 11 0b 1b d6 6f ?? ?? ?? 0a 18 62 d2 58 86 11 07 11 0b 1c d6 6f ?? ?? ?? 0a 17 62 d2 58 86 11 07 11 0b 1d d6 6f ?? ?? ?? 0a 58 86 6f ?? ?? ?? 0a 00 11 0b 1e d6 13 0b 00 11 0b 11 07 6f 6f ?? ?? ?? fe 04 13 18 11 18 3a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}