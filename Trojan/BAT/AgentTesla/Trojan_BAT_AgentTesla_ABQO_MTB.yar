
rule Trojan_BAT_AgentTesla_ABQO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABQO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 08 09 08 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 08 6f 90 01 03 0a 13 04 73 90 01 03 0a 13 05 11 05 11 04 17 73 90 01 03 0a 13 06 11 06 06 16 06 8e 69 6f 90 01 03 0a 11 06 6f 90 01 03 0a 28 90 01 03 0a 11 05 6f 90 01 03 0a 6f 90 01 03 0a 2a 90 0a 60 00 1e 5b 6f 90 01 03 0a 6f 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}