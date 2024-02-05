
rule Trojan_BAT_AgentTesla_NAA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 02 00 00 0a 28 90 01 01 00 00 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 0a dd 90 01 01 00 00 00 90 00 } //01 00 
		$a_01_1 = {43 34 50 52 4f 4c 61 75 6e 63 68 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NAA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {0b 7e 03 00 00 04 28 90 01 01 00 00 0a 0c 07 08 16 08 8e 69 73 90 01 01 00 00 0a 72 90 01 01 00 00 70 72 90 01 01 00 00 70 6f 90 01 01 00 00 0a 00 06 7e 90 01 01 00 00 04 90 00 } //01 00 
		$a_01_1 = {47 61 6d 65 4d 6f 6e 50 52 4f 4b 49 4c 4c } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NAA_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 8e 69 5a 28 90 01 01 00 00 0a 0c 16 0d 06 6f 90 01 01 00 00 0a 07 08 12 03 28 90 01 01 00 00 06 26 09 76 6c d0 90 01 01 00 00 01 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 6c 5b 28 90 01 01 00 00 0a 90 00 } //01 00 
		$a_01_1 = {31 64 32 61 61 30 61 36 2d 32 63 34 62 2d 34 33 36 39 2d 61 66 31 39 2d 65 66 30 33 65 34 33 63 62 64 37 38 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NAA_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.NAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 6a 77 66 64 61 69 64 77 61 00 41 73 73 65 6d 62 6c 79 54 72 61 64 65 6d 61 72 6b 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_01_1 = {6b 6f 69 00 61 6a 77 66 64 61 69 64 77 61 2e 65 78 65 00 6d 73 63 6f 72 6c 69 62 00 53 75 70 70 72 65 73 73 49 6c 64 61 73 6d 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_01_2 = {47 65 74 54 79 70 65 73 } //01 00 
		$a_81_3 = {6a 73 66 65 69 66 65 6f 66 65 77 6f 6c 66 2e 65 78 65 } //01 00 
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_01_5 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_01_7 = {47 65 74 4d 65 74 68 6f 64 } //00 00 
	condition:
		any of ($a_*)
 
}