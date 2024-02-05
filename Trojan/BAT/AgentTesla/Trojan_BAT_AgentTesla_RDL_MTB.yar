
rule Trojan_BAT_AgentTesla_RDL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 39 61 35 33 36 38 31 2d 32 64 37 35 2d 34 34 30 63 2d 39 64 65 36 2d 63 63 30 30 34 34 38 31 35 34 37 37 } //01 00 
		$a_01_1 = {6b 65 72 6e 65 6c 33 32 } //01 00 
		$a_01_2 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //01 00 
		$a_01_3 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //02 00 
		$a_03_4 = {6e 11 08 6a 59 d4 11 04 1e 11 08 59 1e 5a 1f 3f 5f 64 20 90 01 04 6a 5f d2 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}