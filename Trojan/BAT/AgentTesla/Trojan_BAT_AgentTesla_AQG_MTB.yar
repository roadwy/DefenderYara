
rule Trojan_BAT_AgentTesla_AQG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AQG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0a 17 2d 03 26 2b 03 0c 2b 00 73 90 01 03 0a 0d 08 09 28 90 01 03 06 09 16 6a 6f 90 01 03 0a 09 13 04 de 19 08 6f 90 01 03 0a dc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_AQG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AQG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {25 16 09 a2 25 17 90 01 05 a2 25 13 04 14 14 18 90 01 05 25 16 17 9c 25 13 05 17 90 01 05 26 90 00 } //02 00 
		$a_80_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  02 00 
		$a_80_2 = {47 65 74 54 79 70 65 } //GetType  02 00 
		$a_80_3 = {53 69 6d 70 6c 65 55 49 2e 4d 44 49 } //SimpleUI.MDI  00 00 
	condition:
		any of ($a_*)
 
}