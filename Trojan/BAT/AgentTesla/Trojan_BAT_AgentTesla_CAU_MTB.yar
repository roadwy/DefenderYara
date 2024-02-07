
rule Trojan_BAT_AgentTesla_CAU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 1d 06 09 11 04 09 8e 69 5d 91 08 11 04 91 61 d2 6f 90 01 01 00 00 0a 11 04 17 58 16 2d e1 13 04 11 04 08 8e 69 1c 2c fc 90 00 } //01 00 
		$a_01_1 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_CAU_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {2b 41 16 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 72 90 01 01 00 00 70 7e 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 2a 73 90 01 01 00 00 0a 38 90 01 01 ff ff ff 0a 38 90 01 01 ff ff ff 06 2b c2 6f 90 01 01 00 00 0a 2b bd 28 90 01 01 00 00 0a 2b bd 06 2b bc 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_2 = {52 65 70 6c 61 63 65 } //00 00  Replace
	condition:
		any of ($a_*)
 
}