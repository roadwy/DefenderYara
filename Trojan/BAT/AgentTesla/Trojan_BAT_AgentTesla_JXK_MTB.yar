
rule Trojan_BAT_AgentTesla_JXK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JXK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0c 06 08 28 90 01 03 0a 04 da 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0a 00 07 17 d6 0b 07 03 6f 90 01 03 0a fe 04 0d 09 2d cc 90 00 } //01 00 
		$a_01_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}