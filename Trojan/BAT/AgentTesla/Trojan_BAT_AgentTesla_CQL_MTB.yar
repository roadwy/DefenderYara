
rule Trojan_BAT_AgentTesla_CQL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CQL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 06 08 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 6f 90 01 03 0a 08 17 58 0c 08 06 6f 90 01 03 0a 18 5b fe 04 0d 09 2d 90 00 } //01 00 
		$a_01_1 = {47 65 74 54 79 70 65 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_01_3 = {53 75 62 73 74 72 69 6e 67 } //01 00 
		$a_01_4 = {54 6f 42 79 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}