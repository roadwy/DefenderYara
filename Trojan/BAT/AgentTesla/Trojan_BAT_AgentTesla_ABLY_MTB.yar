
rule Trojan_BAT_AgentTesla_ABLY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABLY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {01 25 16 06 17 8d 90 01 03 01 25 16 08 8c 90 01 03 01 a2 14 28 90 01 03 0a 28 90 01 03 0a 1f 10 28 90 01 03 0a 9c 6f 90 01 03 0a 08 17 d6 0c 08 20 90 01 03 00 32 c3 90 0a 3d 00 07 17 8d 90 00 } //01 00 
		$a_01_1 = {53 00 69 00 73 00 74 00 65 00 6d 00 61 00 5f 00 64 00 65 00 5f 00 51 00 75 00 69 00 6e 00 69 00 65 00 6c 00 61 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  Sistema_de_Quiniela.Resources
	condition:
		any of ($a_*)
 
}