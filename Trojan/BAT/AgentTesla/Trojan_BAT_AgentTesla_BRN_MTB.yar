
rule Trojan_BAT_AgentTesla_BRN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BRN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 0b 07 74 90 01 03 01 16 73 90 01 03 0a 0c 1a 8d 90 01 03 01 0d 07 14 72 90 01 03 70 17 8d 90 01 03 01 25 16 07 14 72 90 01 03 70 16 8d 90 01 03 01 14 14 14 28 90 01 03 0a 1b 8c 90 01 03 01 28 90 01 03 0a a2 14 14 28 f0 00 00 0a 00 07 28 90 00 } //01 00 
		$a_81_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_4 = {54 6f 43 68 61 72 41 72 72 61 79 } //00 00  ToCharArray
	condition:
		any of ($a_*)
 
}