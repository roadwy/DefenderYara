
rule Trojan_BAT_AgentTesla_GVC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 19 8d 49 00 00 01 25 16 72 01 00 00 70 a2 25 17 72 13 00 00 70 a2 25 18 72 21 00 00 70 a2 0b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_GVC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 6d c2 8c c9 48 5b fd a8 9f 1e 51 42 60 3c 28 b2 bc 98 4c e3 59 04 d2 9c 5c 97 b3 c1 f1 b4 7c 97 82 31 27 dc a8 40 34 4f 41 24 34 10 10 88 11 7b 37 39 be d6 7b 1d 29 12 01 93 a8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}