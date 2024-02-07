
rule Trojan_BAT_AgentTesla_ASCD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {11 05 8e 69 17 da 13 1e 16 13 1f 2b 1b 11 06 11 05 11 1f 9a 1f 10 28 90 01 01 01 00 0a 86 6f 90 01 01 01 00 0a 00 11 1f 17 d6 13 1f 11 1f 11 1e 31 df 90 00 } //01 00 
		$a_81_1 = {57 69 6e 64 6f 77 73 41 70 70 31 2e 52 65 73 6f 75 72 63 65 73 } //00 00  WindowsApp1.Resources
	condition:
		any of ($a_*)
 
}