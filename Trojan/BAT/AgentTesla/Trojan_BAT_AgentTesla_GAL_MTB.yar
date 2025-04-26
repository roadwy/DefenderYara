
rule Trojan_BAT_AgentTesla_GAL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 0b 16 0a 2b 3b 16 0a 2b 1b 08 07 06 6f ?? 00 00 0a 13 09 09 12 09 28 ?? 00 00 0a 6f ?? 00 00 0a 06 17 58 0a 06 08 6f ?? 00 00 0a 13 07 12 07 28 ?? 00 00 0a fe 04 13 06 11 06 2d cd } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_AgentTesla_GAL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.GAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d0 3f 00 00 01 28 33 00 00 0a 14 72 01 03 00 70 1b 8d 19 00 00 01 25 16 72 1b 03 00 70 7e 48 00 00 0a 72 21 03 00 70 28 ?? ?? ?? 0a a2 25 17 20 00 01 00 00 8c 55 00 00 01 a2 25 1a 17 8d 19 00 00 01 25 16 02 a2 a2 14 14 28 ?? ?? ?? 0a 0a 2b 00 06 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_GAL_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.GAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 16 13 05 16 13 0d 2b 31 00 11 0d 09 5d 13 0e 11 0d 09 5b 13 0f 08 11 0e 11 0f 6f ?? 00 00 0a 13 10 07 11 05 12 10 28 ?? 00 00 0a 9c 11 05 17 58 13 05 00 11 0d 17 58 13 0d 11 0d 09 11 04 5a fe 04 13 11 11 11 2d c1 } //3
		$a_01_1 = {50 00 69 00 7a 00 7a 00 61 00 5f 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //2 Pizza_Project.Properties.Resources
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}