
rule Trojan_BAT_AgentTesla_NZY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {54 56 71 51 24 24 24 24 4d 24 24 24 24 24 24 24 24 45 24 24 24 24 24 24 24 24 2f 2f 38 24 24 24 24 4c 67 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 51 24 24 24 } //1 TVqQ$$$$M$$$$$$$$E$$$$$$$$//8$$$$Lg$$$$$$$$$$$$$$$$$$Q$$$
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_NZY_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 07 1c 8d ?? 00 00 01 25 16 72 ?? 01 00 70 a2 25 17 7e ?? 00 00 04 a2 25 18 72 ?? 01 00 70 a2 25 19 7e } //1
		$a_01_1 = {3f a2 1d 09 02 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 44 00 00 00 0a 00 00 00 0e 00 00 00 24 } //1
		$a_81_2 = {5c 54 65 6d 70 5c 79 33 69 68 6f 34 30 6d 2e 76 62 66 } //1 \Temp\y3iho40m.vbf
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}