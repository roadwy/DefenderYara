
rule Trojan_BAT_AgentTesla_IR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.IR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {01 25 16 03 a2 14 14 14 28 90 01 03 0a 74 90 01 03 01 0a 02 06 72 90 01 03 70 6f 90 01 03 0a 7d 90 01 03 04 2a 90 00 } //01 00 
		$a_81_1 = {53 30 2e 45 4f } //01 00 
		$a_81_2 = {69 6d 69 6d 69 6d 69 6d 69 6d } //01 00 
		$a_81_3 = {4f 62 73 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_81_4 = {00 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 00 61 7a 78 00 } //00 00 
	condition:
		any of ($a_*)
 
}