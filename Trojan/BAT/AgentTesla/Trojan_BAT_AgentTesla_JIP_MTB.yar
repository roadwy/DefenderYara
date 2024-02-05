
rule Trojan_BAT_AgentTesla_JIP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {19 28 e5 6d 73 32 30 32 32 54 72 75 92 8f 32 30 8a 36 54 72 75 6d 70 32 70 32 36 54 72 75 6d 70 } //01 00 
		$a_00_1 = {7c 6a d7 7e 32 84 3b fb 75 ca 74 21 bd 13 64 5a 5f 27 52 05 1f 1f 55 42 53 5b 74 11 14 03 1e 5d } //01 00 
		$a_01_2 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //01 00 
		$a_01_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_01_4 = {54 72 75 6d 70 32 30 32 36 } //00 00 
	condition:
		any of ($a_*)
 
}