
rule Trojan_BAT_AgentTesla_CZA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 0a 00 "
		
	strings :
		$a_03_0 = {03 07 03 6f 90 01 04 5d 17 58 28 90 01 04 28 90 01 04 59 0c 90 09 0c 00 02 07 28 90 01 04 28 90 00 } //0a 00 
		$a_03_1 = {03 07 03 28 90 01 04 5d 17 58 28 90 01 04 28 90 01 04 59 0c 90 09 0c 00 02 07 28 90 01 04 28 90 00 } //01 00 
		$a_01_2 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_01_5 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00  ToCharArray
		$a_01_6 = {00 47 65 74 43 68 61 72 00 } //01 00 
		$a_01_7 = {00 43 68 72 57 00 } //00 00  䌀牨W
	condition:
		any of ($a_*)
 
}