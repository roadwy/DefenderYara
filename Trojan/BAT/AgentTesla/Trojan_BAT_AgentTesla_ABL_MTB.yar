
rule Trojan_BAT_AgentTesla_ABL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {0c 6e 31 03 16 2b 01 17 7e 05 00 00 04 20 8b 09 00 00 95 5a 7e 05 00 00 04 20 97 0c 00 00 95 58 61 80 33 00 00 04 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ABL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {57 dd b6 fd 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 9f 00 00 00 41 00 00 00 dc 01 00 00 19 06 00 00 65 01 00 00 } //01 00 
		$a_01_1 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00 
		$a_01_2 = {49 6e 66 75 73 69 6f 6e } //01 00 
		$a_01_3 = {43 61 72 64 20 50 75 6e 63 68 65 72 } //01 00 
		$a_01_4 = {4c 61 6e 64 73 6b 69 70 20 59 61 72 64 20 43 61 72 65 } //00 00 
	condition:
		any of ($a_*)
 
}