
rule Trojan_BAT_AgentTesla_MAI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 06 07 06 9a 1f 10 28 90 01 03 0a 6f 90 01 03 0a 06 17 58 0a 06 07 8e 69 fe 04 13 09 11 09 2d df 90 00 } //05 00 
		$a_03_1 = {08 06 07 06 9a 1f 10 28 90 01 03 0a d2 6f 90 01 03 0a 06 17 58 0a 06 07 8e 69 fe 04 13 08 11 08 2d de 90 00 } //01 00 
		$a_01_2 = {53 74 72 52 65 76 65 72 73 65 } //01 00 
		$a_01_3 = {67 65 74 5f 4d 61 6e 61 67 65 64 54 68 72 65 61 64 49 64 } //01 00 
		$a_01_4 = {43 6f 6e 74 61 69 6e 65 72 43 6f 6e 74 72 6f 6c } //00 00 
	condition:
		any of ($a_*)
 
}