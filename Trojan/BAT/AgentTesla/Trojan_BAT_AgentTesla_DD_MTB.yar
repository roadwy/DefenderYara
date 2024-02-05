
rule Trojan_BAT_AgentTesla_DD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 01 00 00 01 25 20 90 01 04 20 02 90 01 03 8d 01 00 00 01 25 20 90 01 04 72 90 01 02 1a 70 a2 20 01 90 01 03 9a a2 90 00 } //01 00 
		$a_03_1 = {fe 0c 02 00 74 90 01 01 00 00 01 72 90 01 02 1a 70 72 90 01 02 1a 70 72 90 01 02 1a 70 28 12 00 00 0a fe 0c 02 00 74 02 00 00 1b fe 0c 02 00 74 03 00 00 1b fe 0c 02 00 90 00 } //01 00 
		$a_81_2 = {30 31 32 33 34 35 36 37 38 39 } //00 00 
	condition:
		any of ($a_*)
 
}