
rule Trojan_BAT_AgentTesla_NEB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 00 03 05 1f 16 5d 6f 65 00 00 0a 61 13 01 38 00 00 00 00 38 12 00 00 00 38 0d 00 00 00 00 02 05 04 5d 91 13 00 38 d5 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NEB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {39 32 38 33 65 33 31 63 2d 37 38 32 39 2d 34 64 36 64 2d 39 63 65 36 2d 37 63 36 62 30 61 37 30 65 34 61 37 } //0a 00 
		$a_01_1 = {00 47 65 74 50 69 78 65 6c 00 } //01 00 
		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_01_3 = {00 43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 00 } //01 00 
		$a_01_4 = {00 54 6f 57 69 6e 33 32 00 } //01 00 
		$a_01_5 = {00 44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 00 } //01 00 
		$a_01_6 = {00 47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}