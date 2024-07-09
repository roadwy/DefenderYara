
rule Trojan_BAT_AgentTesla_LLA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 17 62 d2 58 86 11 07 11 0b 1d d6 6f ?? ?? ?? 0a 58 86 6f ?? ?? ?? 0a 00 11 0b 1e d6 13 0b 00 11 0b 11 07 6f ?? ?? ?? 0a fe 04 13 18 11 18 3a 64 ff ff ff } //1
		$a_01_1 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}