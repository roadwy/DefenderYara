
rule Trojan_BAT_AgentTesla_ABOL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABOL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {16 0b 02 8e 69 17 da 0c 2b 17 02 07 91 0d 02 07 02 08 91 9c 02 08 09 9c 07 17 d6 0b 08 17 da 0c 00 07 08 fe 04 13 04 11 04 2d df } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_2 = {4d 00 65 00 74 00 72 00 6f 00 70 00 6f 00 6c 00 69 00 73 00 5f 00 4c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}