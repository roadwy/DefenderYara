
rule Trojan_BAT_AgentTesla_CWI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CWI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 06 02 8e 69 6a 5d d4 02 06 02 8e 69 6a 5d d4 91 03 06 03 8e 69 6a 5d d4 91 61 02 06 17 6a 58 02 8e 69 6a 5d d4 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c } //01 00 
		$a_01_1 = {47 65 74 54 79 70 65 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}