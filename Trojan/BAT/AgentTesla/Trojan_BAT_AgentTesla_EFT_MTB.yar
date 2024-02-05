
rule Trojan_BAT_AgentTesla_EFT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 28 90 01 03 0a 20 9e 02 00 00 da 13 05 11 05 28 90 01 03 0a 28 90 01 03 0a 13 06 07 11 06 28 90 01 03 0a 0b 00 09 17 d6 0d 90 09 0c 00 08 09 6f 90 01 03 0a 28 90 01 03 0a 90 00 } //01 00 
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_81_2 = {47 65 74 4d 65 74 68 6f 64 } //00 00 
	condition:
		any of ($a_*)
 
}