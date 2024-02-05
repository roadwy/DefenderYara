
rule Trojan_BAT_AgentTesla_BOO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BOO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 0d 09 06 20 e8 03 00 00 73 90 01 03 0a 13 04 08 11 04 08 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 00 17 2c b8 08 11 04 08 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 00 08 17 6f 90 01 03 0a 00 1b 2c b8 07 08 6f 90 00 } //01 00 
		$a_81_1 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00 
		$a_81_2 = {47 65 74 54 79 70 65 } //01 00 
		$a_81_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_81_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}