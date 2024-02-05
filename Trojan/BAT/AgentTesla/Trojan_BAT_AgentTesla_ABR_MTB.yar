
rule Trojan_BAT_AgentTesla_ABR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {95 5a 7e 20 00 00 04 20 66 0e 00 00 95 2e 03 16 2b 01 17 17 59 7e 20 00 00 04 20 81 03 00 00 95 5f 7e 20 00 00 04 20 4c 0d 00 00 95 61 58 81 08 00 00 01 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ABR_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 06 00 "
		
	strings :
		$a_03_0 = {06 13 08 11 07 11 08 16 11 08 8e 69 6f 90 01 03 0a 28 90 01 03 0a 09 6f 90 01 03 0a 6f 90 01 03 0a 13 05 de 16 90 0a 2e 00 72 90 01 03 70 28 03 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_01_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00 
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00 
		$a_01_4 = {4a 00 69 00 73 00 77 00 6d 00 75 00 68 00 6b 00 6e 00 66 00 68 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ABR_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.ABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 1f 10 8d 90 01 03 01 25 d0 90 01 03 04 28 90 01 03 06 6f 90 01 03 0a 06 07 6f 90 01 03 0a 17 73 90 01 03 0a 0c 08 02 16 02 8e 69 6f 90 01 03 0a 08 6f 90 01 03 0a 06 28 90 01 03 06 0d 28 90 01 03 06 09 2a 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 42 6c 6f 63 6b } //01 00 
		$a_01_3 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //01 00 
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_01_5 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}