
rule Trojan_BAT_AgentTesla_LAT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 0a 00 "
		
	strings :
		$a_03_0 = {20 df 8e fb 0e 0b 07 20 e7 8e fb 0e fe 01 0c 08 2c 09 20 1f 8f fb 0e 0b 00 2b 61 07 20 f1 8e fb 0e fe 01 0d 09 2c 09 20 18 8f fb 0e 0b 00 2b 4c 00 20 07 8f fb 0e 0b 17 13 04 d0 71 00 00 01 28 90 01 03 0a 14 72 52 1b 00 70 1b 8d 19 00 00 01 25 16 72 a9 cb 00 70 a2 25 17 20 00 01 00 00 8c 6d 00 00 01 a2 25 1a 17 8d 19 00 00 01 25 16 02 a2 a2 14 14 28 90 01 03 0a 0a 2b 00 06 2a 90 00 } //01 00 
		$a_81_1 = {42 6f 72 6e 5f 57 69 6e 64 } //01 00 
		$a_81_2 = {49 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 32 } //01 00 
		$a_81_3 = {47 65 74 4d 65 74 68 6f 64 73 } //01 00 
		$a_81_4 = {49 6e 76 6f 6b 65 } //01 00 
		$a_81_5 = {47 65 74 54 79 70 65 73 } //01 00 
		$a_81_6 = {54 6f 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}