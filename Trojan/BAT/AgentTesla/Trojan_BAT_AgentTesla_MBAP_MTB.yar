
rule Trojan_BAT_AgentTesla_MBAP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 04 03 8e 69 5d 91 06 04 1f 16 5d 91 61 28 ?? ?? ?? 0a 03 04 17 58 03 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_MBAP_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 11 07 07 8e 69 5d 07 11 07 07 8e 69 5d 91 08 11 07 1f 16 5d 91 61 28 ?? 00 00 0a 07 11 07 17 58 07 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 } //1
		$a_81_1 = {38 35 37 48 34 38 37 5a 53 48 39 37 51 34 48 5a 42 38 37 34 43 43 } //1 857H487ZSH97Q4HZB874CC
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}