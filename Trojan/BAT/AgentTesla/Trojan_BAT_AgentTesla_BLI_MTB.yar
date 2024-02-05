
rule Trojan_BAT_AgentTesla_BLI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BLI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 50 8e 69 6a 5d b7 03 50 90 01 01 03 50 8e 69 6a 5d b7 91 90 01 03 8e 69 6a 5d b7 91 61 03 50 90 01 01 17 6a d6 03 50 8e 69 6a 5d b7 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_BLI_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BLI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {07 02 09 18 28 90 01 03 06 1f 10 28 90 01 03 06 84 28 90 01 03 0a 6f 90 01 03 0a 26 09 18 d6 0d 20 05 00 00 00 28 90 01 03 06 3a 90 01 04 26 09 08 3e 90 00 } //01 00 
		$a_00_1 = {02 02 8e 69 17 da 91 1f 70 61 0c 02 8e 69 17 d6 17 da 17 d6 } //00 00 
	condition:
		any of ($a_*)
 
}