
rule Trojan_BAT_AgentTesla_BFV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {06 16 9a 18 3a 90 01 04 26 38 90 01 04 11 01 02 28 90 01 03 06 6f 90 01 03 0a 11 00 11 01 6f 90 01 03 0a 6f 90 01 03 0a 1e 3a 90 01 04 26 11 02 17 8d 90 01 03 01 25 16 02 28 90 01 03 06 a2 6f 90 01 03 0a 74 90 00 } //01 00 
		$a_81_1 = {43 6c 61 73 73 4c 69 62 72 61 72 79 31 } //01 00 
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_81_3 = {47 65 74 4d 65 74 68 6f 64 } //00 00 
	condition:
		any of ($a_*)
 
}