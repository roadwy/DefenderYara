
rule Trojan_BAT_AgentTesla_MM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {a2 25 17 7e 90 01 02 00 04 a2 25 18 72 90 01 02 00 70 a2 0a 28 90 01 02 00 06 16 28 90 01 02 00 06 28 90 01 02 00 0a 06 28 90 01 02 00 06 00 2a 90 09 07 00 25 16 7e 90 01 02 00 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_MM_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00 
		$a_01_1 = {54 6f 41 72 72 61 79 } //01 00 
		$a_01_2 = {47 5a 69 70 53 74 72 65 61 6d } //01 00 
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_01_4 = {47 65 74 44 6f 6d 61 69 6e } //01 00 
		$a_01_5 = {54 00 55 00 46 00 48 00 6b 00 74 00 49 00 31 00 78 00 46 00 32 00 38 00 44 00 71 00 72 00 75 00 53 00 73 00 68 00 } //01 00 
		$a_01_6 = {78 00 54 00 43 00 49 00 49 00 79 00 67 00 62 00 76 00 4c 00 } //00 00 
	condition:
		any of ($a_*)
 
}