
rule Trojan_BAT_AgentTesla_BEM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {03 11 04 18 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 04 07 90 01 05 28 90 01 04 6a 61 b7 28 90 01 03 0a 28 90 01 03 0a 13 05 08 11 05 90 01 05 26 07 04 90 01 05 17 da 90 00 } //01 00 
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //01 00  FromBase64CharArray
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_3 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } //01 00  ISectionEntry
		$a_81_4 = {58 4f 52 5f 44 65 63 72 79 70 74 } //00 00  XOR_Decrypt
	condition:
		any of ($a_*)
 
}