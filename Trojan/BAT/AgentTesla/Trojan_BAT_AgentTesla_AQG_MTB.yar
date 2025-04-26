
rule Trojan_BAT_AgentTesla_AQG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AQG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 17 2d 03 26 2b 03 0c 2b 00 73 ?? ?? ?? 0a 0d 08 09 28 ?? ?? ?? 06 09 16 6a 6f ?? ?? ?? 0a 09 13 04 de 19 08 6f ?? ?? ?? 0a dc } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_BAT_AgentTesla_AQG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AQG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {25 16 09 a2 25 17 ?? ?? ?? ?? ?? a2 25 13 04 14 14 18 ?? ?? ?? ?? ?? 25 16 17 9c 25 13 05 17 ?? ?? ?? ?? ?? 26 } //10
		$a_80_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  2
		$a_80_2 = {47 65 74 54 79 70 65 } //GetType  2
		$a_80_3 = {53 69 6d 70 6c 65 55 49 2e 4d 44 49 } //SimpleUI.MDI  2
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=16
 
}