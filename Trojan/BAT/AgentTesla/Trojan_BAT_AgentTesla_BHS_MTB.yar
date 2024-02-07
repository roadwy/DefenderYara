
rule Trojan_BAT_AgentTesla_BHS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {11 06 02 11 06 91 08 61 07 11 07 91 61 b4 9c 11 07 03 28 90 01 03 06 17 da 90 00 } //0a 00 
		$a_02_1 = {02 02 8e 69 17 da 91 1f 70 61 0c 02 8e 69 17 d6 17 da 17 d6 8d 90 01 03 01 0d 02 8e 69 17 da 90 00 } //01 00 
		$a_81_2 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_3 = {47 65 74 4d 65 74 68 6f 64 } //00 00  GetMethod
	condition:
		any of ($a_*)
 
}