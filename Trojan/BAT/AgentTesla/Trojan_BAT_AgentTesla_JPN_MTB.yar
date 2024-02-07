
rule Trojan_BAT_AgentTesla_JPN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 06 07 02 07 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0d 09 2d dc 90 00 } //01 00 
		$a_81_1 = {36 38 30 30 37 34 30 30 37 34 30 30 } //01 00  680074007400
		$a_81_2 = {37 30 30 30 37 33 30 30 33 41 30 30 32 46 30 30 32 46 } //00 00  700073003A002F002F
	condition:
		any of ($a_*)
 
}