
rule Trojan_BAT_AgentTesla_GAT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {13 04 16 13 05 16 13 06 2b 31 00 11 05 09 5d 13 0a 11 05 09 5b 13 0b 08 11 0a 11 0b 6f 90 01 01 00 00 0a 13 0c 07 11 06 12 0c 28 90 01 01 00 00 0a 9c 11 06 17 58 13 06 11 05 17 58 13 05 00 11 05 09 11 04 5a fe 04 13 0d 11 0d 2d c1 90 00 } //05 00 
		$a_03_1 = {13 04 16 13 05 16 13 06 2b 31 00 11 05 09 5d 13 08 11 05 09 5b 13 09 08 11 08 11 09 6f 90 01 01 00 00 0a 13 0a 07 11 06 12 0a 28 90 01 01 00 00 0a 9c 11 06 17 58 13 06 11 05 17 58 13 05 00 11 05 09 11 04 5a fe 04 13 0b 11 0b 2d c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_GAT_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.GAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 0a 00 "
		
	strings :
		$a_03_0 = {20 df 8e fb 0e 0b 07 20 e7 8e fb 0e fe 01 0c 08 2c 09 20 1f 8f fb 0e 0b 00 2b 61 07 20 f1 8e fb 0e fe 01 0d 09 2c 09 20 18 8f fb 0e 0b 00 2b 4c 00 20 07 8f fb 0e 0b 17 13 04 d0 99 00 00 01 28 90 01 03 0a 14 72 27 bc 00 70 1b 8d 19 00 00 01 25 16 72 41 bc 00 70 a2 25 17 20 00 01 00 00 8c 82 00 00 01 a2 25 1a 17 8d 19 00 00 01 25 16 02 a2 a2 14 14 28 90 01 03 0a 0a 2b 00 06 2a 90 00 } //01 00 
		$a_81_1 = {46 6c 61 70 70 79 42 69 72 64 } //01 00  FlappyBird
		$a_81_2 = {49 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 32 } //01 00  I______________________2
		$a_81_3 = {47 65 74 4d 65 74 68 6f 64 73 } //01 00  GetMethods
		$a_81_4 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_81_5 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_81_6 = {54 6f 53 74 72 69 6e 67 } //00 00  ToString
	condition:
		any of ($a_*)
 
}