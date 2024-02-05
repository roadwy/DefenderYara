
rule Trojan_BAT_AgentTesla_NEAQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {33 66 36 63 33 35 36 34 2d 31 37 39 35 2d 34 35 38 34 2d 38 61 34 38 2d 62 37 32 30 63 62 33 30 65 61 38 61 } //02 00 
		$a_01_1 = {48 47 67 47 47 67 37 2e 65 78 65 } //01 00 
		$a_01_2 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 20 31 2e 36 } //00 00 
	condition:
		any of ($a_*)
 
}