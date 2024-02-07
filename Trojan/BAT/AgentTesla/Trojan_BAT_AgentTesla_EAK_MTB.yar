
rule Trojan_BAT_AgentTesla_EAK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {0c 16 13 04 2b 17 00 08 11 04 07 11 04 9a 1f 10 28 90 01 01 00 00 0a 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 05 11 05 2d dc 90 00 } //01 00 
		$a_01_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_2 = {43 75 73 74 6f 6d 65 72 73 5f 53 69 6d 75 6c 61 74 69 6f 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Customers_Simulation.Properties.Resources
		$a_01_3 = {53 70 6c 69 74 } //01 00  Split
		$a_01_4 = {52 65 70 6c 61 63 65 } //00 00  Replace
	condition:
		any of ($a_*)
 
}