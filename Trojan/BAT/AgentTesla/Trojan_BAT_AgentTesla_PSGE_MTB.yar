
rule Trojan_BAT_AgentTesla_PSGE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {28 2c 00 00 06 11 0a 20 bd 2b ba 0e 5a 20 b7 6c 9a 9e 61 38 0f dd ff ff 28 66 01 00 06 28 35 00 00 06 72 05 04 00 70 72 09 04 00 70 28 36 00 00 06 72 11 04 00 70 72 15 04 00 70 28 36 00 00 06 72 19 04 00 70 72 f5 00 00 70 28 36 00 00 06 0b 11 0a } //01 00 
		$a_01_1 = {49 45 6e 75 6d 65 72 61 74 6f 72 } //01 00 
		$a_01_2 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}