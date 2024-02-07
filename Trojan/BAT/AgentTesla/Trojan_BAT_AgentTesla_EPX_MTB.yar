
rule Trojan_BAT_AgentTesla_EPX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 11 04 17 da 6f 90 01 03 0a 07 11 04 07 6f 90 01 03 0a 5d 6f 90 01 03 0a da 13 05 08 11 05 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0c 11 04 17 d6 13 04 90 00 } //01 00 
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_2 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //01 00  GetTypeFromHandle
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}