
rule Trojan_BAT_AgentTesla_AMAJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 05 25 4b 11 0c 11 0f 1f 0f 5f 95 61 54 11 0c 11 0f 1f 0f 5f 11 0c 11 0f 1f 0f 5f 95 11 05 25 1a 58 13 05 4b 61 20 90 01 04 58 9e 11 0f 17 58 13 0f 11 16 17 58 13 16 11 16 11 06 37 c1 90 00 } //01 00 
		$a_80_1 = {4e 4d 4b 4c 50 4f 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //NMKLPO.Properties.Resources  00 00 
	condition:
		any of ($a_*)
 
}