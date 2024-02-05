
rule Trojan_BAT_AgentTesla_NEC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 28 90 01 03 0a 20 90 01 03 00 da 13 05 11 05 28 90 01 03 0a 28 90 01 03 0a 13 06 07 11 06 28 90 01 03 0a 28 90 01 03 0a 0b 00 09 17 d6 0d 09 08 6f 90 01 03 0a fe 04 13 07 11 07 2d b3 90 00 } //01 00 
		$a_01_1 = {f4 02 0f 03 ef 02 df 02 df 02 eb 02 df 02 df 02 df 02 df 02 e3 02 df 02 df 02 df 02 df 02 cd 02 cd 02 d6 02 df 02 df 02 ea 02 05 03 df 02 df 02 df } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NEC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 00 78 00 43 00 20 00 74 00 69 00 6d 00 65 00 78 00 6f 00 75 00 74 00 20 00 2f 00 6e 00 6f 00 62 00 72 00 78 00 65 00 61 00 6b 00 20 00 2f 00 74 00 20 00 31 00 39 00 } //01 00 
		$a_01_1 = {53 00 63 00 61 00 6e 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 2d 00 70 00 64 00 66 00 5f 00 56 00 65 00 6c 00 66 00 63 00 76 00 77 00 69 00 2e 00 6a 00 70 00 67 00 } //01 00 
		$a_01_2 = {4b 00 75 00 6a 00 67 00 77 00 64 00 } //01 00 
		$a_01_3 = {49 00 65 00 7a 00 64 00 66 00 71 00 6f 00 79 00 68 00 63 00 61 00 } //01 00 
		$a_01_4 = {54 00 67 00 61 00 75 00 69 00 70 00 6d 00 72 00 78 00 72 00 6b 00 64 00 6a 00 64 00 79 00 69 00 72 00 } //01 00 
		$a_01_5 = {56 00 71 00 6d 00 67 00 6b 00 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}