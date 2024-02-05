
rule Trojan_BAT_AgentTesla_LHC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 11 04 11 05 6f 90 01 03 0a 26 09 11 04 11 05 6f 90 01 03 0a 13 06 16 13 07 02 11 06 28 90 01 03 06 13 07 08 07 11 07 d2 9c 11 05 17 58 13 05 11 05 17 32 cb 90 00 } //01 00 
		$a_01_1 = {54 6f 57 69 6e 33 32 } //01 00 
		$a_01_2 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //01 00 
		$a_01_3 = {47 65 74 50 69 78 65 6c } //00 00 
	condition:
		any of ($a_*)
 
}