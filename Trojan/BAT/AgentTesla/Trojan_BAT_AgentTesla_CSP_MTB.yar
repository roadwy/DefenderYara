
rule Trojan_BAT_AgentTesla_CSP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 11 04 07 11 04 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 8c 90 01 03 01 6f 90 01 03 0a 00 00 11 04 17 58 13 04 11 04 07 6f 90 01 03 0a 18 5b 90 00 } //01 00 
		$a_01_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_2 = {43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 } //01 00  CreateInstance
		$a_01_3 = {50 00 61 00 6e 00 61 00 6d 00 65 00 72 00 61 00 2e 00 50 00 6f 00 72 00 73 00 63 00 68 00 65 00 } //00 00  Panamera.Porsche
	condition:
		any of ($a_*)
 
}