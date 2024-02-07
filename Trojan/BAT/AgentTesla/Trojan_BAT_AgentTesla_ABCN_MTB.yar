
rule Trojan_BAT_AgentTesla_ABCN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 90 01 03 0a 6e 02 07 17 58 02 8e 69 5d 91 28 90 01 03 0a 6a 59 20 90 01 03 00 6a 58 20 90 01 03 00 6a 5d d2 9c 07 15 58 0b 90 00 } //01 00 
		$a_01_1 = {53 69 6d 46 61 72 6d 2e 45 63 6f 46 61 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //01 00  SimFarm.EcoFarm.resources
		$a_01_2 = {45 00 6c 00 65 00 63 00 74 00 72 00 6f 00 } //00 00  Electro
	condition:
		any of ($a_*)
 
}