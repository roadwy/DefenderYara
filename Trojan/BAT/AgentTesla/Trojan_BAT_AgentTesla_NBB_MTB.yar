
rule Trojan_BAT_AgentTesla_NBB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 6c 23 ff b9 f4 ee 2a 81 f7 3f 5b 28 90 01 03 0a b7 28 90 01 03 0a 28 90 01 03 0a 2a 90 00 } //01 00 
		$a_03_1 = {2b 1e 07 08 6f 90 01 03 0a 28 90 01 03 06 28 90 01 03 0a 0d 06 09 28 90 01 03 0a 0a 08 17 d6 0c 08 07 6f 90 01 03 0a 32 d9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NBB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {6f 53 00 00 0a 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 06 18 6f 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 0c 02 0d 08 09 16 09 8e b7 6f 90 01 01 00 00 0a 90 00 } //01 00 
		$a_01_1 = {74 61 73 6b 73 68 6f 73 74 77 } //01 00 
		$a_01_2 = {58 00 30 00 4b 00 4d 00 44 00 67 00 64 00 37 00 44 00 57 00 6e 00 48 00 54 00 56 00 30 00 41 00 71 00 } //00 00 
	condition:
		any of ($a_*)
 
}