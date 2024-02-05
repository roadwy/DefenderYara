
rule Trojan_BAT_AgentTesla_PK_MSR{
	meta:
		description = "Trojan:BAT/AgentTesla.PK!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {00 08 11 04 07 11 04 18 5a 18 6f 90 01 04 1f 10 28 90 01 04 9c 00 11 04 17 58 13 04 11 04 08 8e 69 fe 04 90 00 } //01 00 
		$a_00_1 = {53 75 62 73 74 72 69 6e 67 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_01_3 = {54 6f 42 79 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}