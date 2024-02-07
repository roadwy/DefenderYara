
rule Trojan_BAT_AgentTesla_EDI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 08 06 08 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 90 00 } //01 00 
		$a_00_1 = {4f 00 30 00 2e 00 7a 00 43 00 } //01 00  O0.zC
		$a_01_2 = {00 47 65 74 54 79 70 65 00 } //01 00 
		$a_01_3 = {00 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 00 } //01 00  䌀敲瑡䥥獮慴据e
		$a_01_4 = {00 53 75 62 73 74 72 69 6e 67 00 } //00 00 
	condition:
		any of ($a_*)
 
}