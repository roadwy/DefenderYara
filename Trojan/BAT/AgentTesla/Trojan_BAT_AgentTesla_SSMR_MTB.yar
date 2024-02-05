
rule Trojan_BAT_AgentTesla_SSMR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SSMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {42 69 74 6d 61 70 } //01 00 
		$a_81_1 = {47 65 74 50 69 78 65 6c } //01 00 
		$a_81_2 = {41 73 73 65 6d 62 6c 79 } //01 00 
		$a_81_3 = {00 63 79 7a 00 } //01 00 
		$a_81_4 = {00 78 73 61 00 } //01 00 
		$a_81_5 = {00 4c 65 76 65 6c 00 } //01 00 
		$a_81_6 = {47 65 74 54 79 70 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}