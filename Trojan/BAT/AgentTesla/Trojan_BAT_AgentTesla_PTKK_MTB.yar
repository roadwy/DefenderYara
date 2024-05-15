
rule Trojan_BAT_AgentTesla_PTKK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 08 02 16 02 8e 69 6f 81 00 00 0a 00 11 08 6f 82 00 00 0a 00 11 07 6f 83 00 00 0a 0c de 0e } //02 00 
		$a_03_1 = {11 04 6f 29 01 00 0a 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 0a 2b 00 06 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}