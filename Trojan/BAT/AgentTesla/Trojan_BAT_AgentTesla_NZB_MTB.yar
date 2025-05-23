
rule Trojan_BAT_AgentTesla_NZB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 01 17 58 13 01 ?? ?? ?? ?? 00 11 00 7e ?? ?? ?? 04 11 01 7e ?? ?? ?? 04 8e 69 5d 91 02 11 01 91 61 d2 6f ?? ?? ?? 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_NZB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 00 56 00 71 00 51 00 24 00 24 00 24 00 24 00 4d 00 24 00 24 00 24 00 24 00 24 00 24 00 24 00 24 00 45 00 24 00 24 00 24 00 24 00 24 00 24 00 24 00 24 00 2f 00 2f 00 38 00 24 00 24 00 24 } //1
		$a_01_1 = {24 00 24 00 51 00 43 00 46 00 6e 00 30 00 6b 00 24 00 24 00 24 00 24 00 24 00 24 00 45 00 24 00 24 00 68 00 38 00 4f 00 66 00 53 00 55 00 24 00 24 00 24 00 24 00 24 00 24 00 51 00 43 00 4b } //1
		$a_01_2 = {51 00 24 00 24 00 24 00 24 00 24 00 24 00 45 00 6c 00 4a 00 53 00 54 00 24 00 24 00 24 00 24 00 50 00 48 00 52 00 34 00 64 00 46 00 4e 00 6c 00 59 00 58 00 4a 00 6a 00 61 00 46 00 39 00 55 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}