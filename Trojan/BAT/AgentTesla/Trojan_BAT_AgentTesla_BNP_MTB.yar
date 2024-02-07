
rule Trojan_BAT_AgentTesla_BNP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {02 09 18 28 90 01 03 06 1f 10 28 90 01 03 06 84 28 90 01 03 06 28 90 01 03 06 26 90 00 } //01 00 
		$a_02_1 = {09 02 8e 69 18 da 17 d6 17 da 17 d6 8d 90 01 03 01 28 90 01 03 06 74 90 01 03 1b 0a 90 00 } //01 00 
		$a_81_2 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_3 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_81_4 = {65 6b 6f 76 6e 49 } //00 00  ekovnI
	condition:
		any of ($a_*)
 
}