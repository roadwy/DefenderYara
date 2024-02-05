
rule Trojan_BAT_AgentTesla_DTG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DTG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {d1 2f 7a 5f ab 8f 7d 9c d4 7a 5f 1a 7d 2e e5 03 d1 33 cf 05 44 ff 39 1e 62 a7 a9 6f ca d3 df 69 e7 b5 7e 30 eb 49 3a eb c9 7c 62 6f 21 4d bf 86 } //01 00 
		$a_01_1 = {ee da fe 8c 1d dc 1f 92 46 df a4 13 9c 99 4b a7 3f e6 bf 1c 52 7f e2 cc b4 c3 1c } //00 00 
	condition:
		any of ($a_*)
 
}