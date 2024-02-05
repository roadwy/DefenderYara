
rule Trojan_BAT_AgentTesla_AQQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AQQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {08 09 16 09 8e 69 90 01 05 13 04 11 04 2c 0a 07 09 16 11 04 90 01 05 11 04 09 8e 69 2e de 90 00 } //0a 00 
		$a_03_1 = {20 00 01 00 00 14 11 09 17 90 01 05 25 16 02 90 01 05 a2 90 01 0a 0d de 30 11 07 17 58 13 07 11 07 11 06 8e 69 32 97 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}