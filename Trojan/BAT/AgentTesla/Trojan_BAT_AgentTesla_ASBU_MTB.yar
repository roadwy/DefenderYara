
rule Trojan_BAT_AgentTesla_ASBU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASBU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {16 13 22 2b 44 00 16 13 23 2b 2c 00 09 11 04 11 22 58 11 21 11 23 58 6f 90 01 01 01 00 0a 13 24 12 24 28 90 01 01 01 00 0a 13 25 08 07 11 25 9c 07 17 58 0b 11 23 17 58 13 23 00 11 23 17 fe 04 13 26 11 26 2d c9 90 00 } //01 00 
		$a_81_1 = {49 6e 74 65 72 66 61 63 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00  Interface.Properties.Resources
	condition:
		any of ($a_*)
 
}