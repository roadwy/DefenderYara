
rule Trojan_BAT_AgentTesla_CGU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CGU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 03 05 03 8e 69 5d 91 05 04 03 8e 69 5d d6 04 5f 61 b4 28 } //01 00 
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_2 = {47 65 74 54 79 70 65 } //00 00  GetType
	condition:
		any of ($a_*)
 
}