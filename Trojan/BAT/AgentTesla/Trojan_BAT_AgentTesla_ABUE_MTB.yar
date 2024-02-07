
rule Trojan_BAT_AgentTesla_ABUE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABUE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {16 13 07 2b 23 07 08 06 11 07 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a b4 6f d6 00 00 0a 00 08 17 90 01 01 0c 11 07 18 d6 13 07 11 07 11 06 31 d7 90 00 } //01 00 
		$a_01_1 = {70 00 72 00 79 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 74 00 6f 00 63 00 6b 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  pryControlStock.Resources
	condition:
		any of ($a_*)
 
}