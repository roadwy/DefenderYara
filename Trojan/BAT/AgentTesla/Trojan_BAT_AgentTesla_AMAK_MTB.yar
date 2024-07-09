
rule Trojan_BAT_AgentTesla_AMAK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 00 0e 04 28 ?? 00 00 06 00 7e ?? 00 00 04 6f ?? 00 00 0a 05 16 03 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a } //1
		$a_80_1 = {65 6e 67 69 6e 65 70 6f 6c 6c 75 74 69 6f 6e 66 72 69 65 6e 64 6c 79 } //enginepollutionfriendly  1
	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}