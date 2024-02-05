
rule Trojan_BAT_AgentTesla_OH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {07 11 04 11 06 6f 90 02 04 13 07 11 07 28 90 02 04 13 08 08 06 11 08 b4 9c 11 06 17 d6 13 06 11 06 11 05 31 d9 90 00 } //01 00 
		$a_81_1 = {47 65 74 50 69 78 65 6c } //01 00 
		$a_81_2 = {54 6f 57 69 6e 33 32 } //01 00 
		$a_81_3 = {52 65 61 64 4f 6e 6c 79 44 69 63 74 69 6f 6e 61 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}