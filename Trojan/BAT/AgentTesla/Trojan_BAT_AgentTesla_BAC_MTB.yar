
rule Trojan_BAT_AgentTesla_BAC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {70 18 18 8d 90 01 03 01 25 16 09 8c 90 01 03 01 a2 25 17 11 04 8c 90 01 03 01 a2 28 90 01 03 0a 25 2d 0d 26 12 0b 90 01 06 11 0b 2b 05 90 01 05 13 09 11 09 28 90 01 03 0a 13 0a 07 06 11 0a b4 9c 11 04 17 d6 13 04 11 04 11 08 31 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_BAC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {18 9a 19 95 6e 31 03 16 2b 01 17 17 59 7e 23 00 00 04 18 9a 1f 77 95 5f 7e 23 00 00 04 18 9a 20 c8 02 00 00 95 61 58 80 34 00 00 04 } //0a 00 
		$a_01_1 = {20 f8 0a 00 00 95 2e 05 16 07 0c 2b 01 17 7e 42 00 00 04 20 7a 04 00 00 95 5a 7e 42 00 00 04 20 76 0d 00 00 95 58 61 81 06 00 00 01 } //0a 00 
		$a_01_2 = {16 2b 01 17 17 59 7e 33 00 00 04 1b 9a 20 2a 07 00 00 95 5f 7e 33 00 00 04 1b 9a 20 eb 08 00 00 95 61 58 81 07 00 00 01 } //0a 00 
		$a_01_3 = {95 2e 03 16 2b 01 17 17 59 7e 7b 00 00 04 1b 9a 20 0f 08 00 00 95 5f 7e 7b 00 00 04 1b 9a 20 ff 09 00 00 95 61 61 81 09 00 00 01 } //0a 00 
		$a_01_4 = {16 9a 20 18 03 00 00 95 2e 03 16 2b 01 17 17 59 7e 21 01 00 04 16 9a 07 0b 20 d0 0b 00 00 95 5f 7e 21 01 00 04 16 9a 20 c0 09 00 00 95 61 58 81 08 00 00 01 } //00 00 
	condition:
		any of ($a_*)
 
}