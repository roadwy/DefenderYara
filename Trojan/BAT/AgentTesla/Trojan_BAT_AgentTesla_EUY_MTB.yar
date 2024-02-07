
rule Trojan_BAT_AgentTesla_EUY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EUY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {35 00 44 00 38 00 46 00 48 00 45 00 47 00 47 00 42 00 34 00 47 00 47 00 48 00 46 00 35 00 35 00 48 00 41 00 37 00 34 00 56 00 43 00 } //01 00  5D8FHEGGB4GGHF55HA74VC
		$a_01_1 = {43 00 6f 00 66 00 66 00 65 00 65 00 } //01 00  Coffee
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}