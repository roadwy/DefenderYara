
rule Trojan_BAT_AgentTesla_DFM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {08 09 11 04 6f 90 01 03 0a 13 05 08 09 11 04 6f 90 01 03 0a 13 06 11 06 28 90 01 03 0a 13 07 07 06 11 07 d2 9c 90 00 } //01 00 
		$a_01_1 = {47 65 74 50 69 78 65 6c } //01 00 
		$a_01_2 = {54 6f 57 69 6e 33 32 } //01 00 
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_01_4 = {47 65 74 54 79 70 65 } //00 00 
	condition:
		any of ($a_*)
 
}