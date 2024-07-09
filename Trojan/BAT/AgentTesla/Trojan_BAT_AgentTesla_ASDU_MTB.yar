
rule Trojan_BAT_AgentTesla_ASDU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASDU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 07 11 10 17 8d ?? 00 00 01 25 16 11 06 11 10 9a 1f 10 28 ?? 00 00 0a b4 9c 6f ?? 00 00 0a 00 11 10 17 d6 13 10 11 10 11 0f 31 } //1
		$a_01_1 = {6e 00 6a 00 6b 00 77 00 64 00 73 00 68 00 20 00 75 00 64 00 68 00 67 00 6b 00 75 00 79 00 6a 00 64 00 67 00 79 00 6b 00 75 00 77 00 6a 00 64 00 67 00 } //1 njkwdsh udhgkuyjdgykuwjdg
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}