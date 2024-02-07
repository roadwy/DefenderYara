
rule Trojan_BAT_AgentTesla_NYU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NYU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {25 16 16 8c 03 00 00 01 a2 25 17 19 8d 90 01 03 01 25 16 28 90 01 03 06 16 9a a2 25 17 90 00 } //01 00 
		$a_01_1 = {50 69 72 61 74 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00  Pirates.Resources
	condition:
		any of ($a_*)
 
}