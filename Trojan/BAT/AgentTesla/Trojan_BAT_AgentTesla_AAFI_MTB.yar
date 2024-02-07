
rule Trojan_BAT_AgentTesla_AAFI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AAFI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {13 05 11 04 8e 69 17 da 13 12 16 13 13 2b 1c 11 05 11 13 11 04 11 13 9a 1f 10 28 90 01 01 01 00 0a 6f 90 01 01 01 00 0a 00 11 13 17 d6 13 13 11 13 11 12 31 de 90 00 } //01 00 
		$a_01_1 = {43 00 6f 00 6d 00 69 00 63 00 6c 00 61 00 6e 00 64 00 69 00 61 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  Comiclandia.Resources
	condition:
		any of ($a_*)
 
}