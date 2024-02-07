
rule Trojan_BAT_AgentTesla_FAO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {18 da 13 06 16 13 07 2b 1e 08 07 11 07 18 6f 90 01 01 01 00 0a 1f 10 28 90 01 01 01 00 0a b4 6f 90 01 01 01 00 0a 00 11 07 18 d6 13 07 11 07 11 06 31 dc 90 00 } //02 00 
		$a_01_1 = {50 00 72 00 69 00 73 00 63 00 69 00 6c 00 6c 00 61 00 5f 00 54 00 61 00 79 00 6c 00 6f 00 72 00 } //00 00  Priscilla_Taylor
	condition:
		any of ($a_*)
 
}