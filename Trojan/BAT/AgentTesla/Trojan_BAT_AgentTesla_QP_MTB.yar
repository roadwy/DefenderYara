
rule Trojan_BAT_AgentTesla_QP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.QP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0d 09 08 6f 90 01 03 0a 00 09 18 6f 90 01 03 0a 00 09 6f 90 01 03 0a 06 16 06 8e 69 6f 90 01 03 0a 13 04 11 04 02 90 00 } //01 00 
		$a_81_1 = {48 34 46 5a 54 47 43 58 38 37 58 34 38 42 46 37 34 47 42 35 38 38 } //01 00 
		$a_01_2 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_3 = {47 65 74 42 79 74 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}