
rule Trojan_BAT_AgentTesla_BN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_02_0 = {03 11 04 18 90 01 05 28 90 01 04 28 90 01 04 04 07 90 01 05 28 90 01 04 6a 61 b7 28 90 01 04 13 07 90 00 } //01 00 
		$a_80_1 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } //ISectionEntry  01 00 
		$a_80_2 = {47 65 74 54 79 70 65 } //GetType  01 00 
		$a_80_3 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  01 00 
		$a_80_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  01 00 
		$a_80_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  00 00 
	condition:
		any of ($a_*)
 
}