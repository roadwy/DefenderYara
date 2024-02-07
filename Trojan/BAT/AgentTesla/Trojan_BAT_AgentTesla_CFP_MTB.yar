
rule Trojan_BAT_AgentTesla_CFP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {08 09 9a 13 04 00 06 11 04 1f 10 28 90 01 03 0a d1 13 05 12 05 28 90 01 03 0a 28 90 01 03 0a 0a 00 09 17 58 0d 09 08 8e 69 32 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_2 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //01 00  GetTypeFromHandle
		$a_01_3 = {54 6f 49 6e 74 33 32 } //01 00  ToInt32
		$a_01_4 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_5 = {54 6f 43 68 61 72 41 72 72 61 79 } //00 00  ToCharArray
	condition:
		any of ($a_*)
 
}