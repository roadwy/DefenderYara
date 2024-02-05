
rule Trojan_BAT_AgentTesla_LUC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LUC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 6c 23 ff 90 01 06 3f 5b 28 90 01 03 0a b7 28 90 01 03 0a 28 90 01 03 0a 2a 90 00 } //01 00 
		$a_01_1 = {0a 0d 06 09 28 8b 00 00 0a 0a 08 17 d6 0c 08 07 6f 8c 00 00 0a 32 d9 } //01 00 
		$a_03_2 = {0a 0d 06 09 28 90 01 03 0a 0a 08 17 d6 0c 08 07 6f 90 01 03 0a 32 d9 90 00 } //01 00 
		$a_01_3 = {64 00 5f 00 ac 00 5f 00 5f 00 71 00 5f 00 4c 00 62 00 5f 00 b3 00 5f 00 97 00 70 00 5f 00 65 } //00 00 
	condition:
		any of ($a_*)
 
}