
rule Trojan_BAT_AgentTesla_ASCG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {11 06 8e 69 17 da 13 1f 16 13 20 2b 1b 11 07 11 06 11 20 9a 1f 10 28 90 01 01 00 00 0a 86 6f 90 01 01 00 00 0a 00 11 20 17 d6 13 20 11 20 11 1f 31 df 90 00 } //01 00 
		$a_81_1 = {6c 61 62 36 2e 52 65 73 6f 75 72 63 65 73 } //00 00  lab6.Resources
	condition:
		any of ($a_*)
 
}