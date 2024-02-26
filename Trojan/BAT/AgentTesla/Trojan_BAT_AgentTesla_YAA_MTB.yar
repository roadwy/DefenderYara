
rule Trojan_BAT_AgentTesla_YAA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 73 6f 6c 76 65 53 74 72 61 74 65 67 79 } //01 00  ResolveStrategy
		$a_01_1 = {4d 64 75 77 6f 6b 64 2e 41 6e 6e 6f 74 61 74 69 6f 6e 73 } //01 00  Mduwokd.Annotations
		$a_01_2 = {4d 64 75 77 6f 6b 64 2e 53 74 61 74 65 73 } //01 00  Mduwokd.States
		$a_01_3 = {50 6f 6c 69 63 79 45 72 72 6f 72 53 74 61 74 75 73 } //01 00  PolicyErrorStatus
		$a_01_4 = {73 05 00 00 0a 72 01 00 00 70 28 0c 00 00 06 13 00 20 00 00 00 00 } //01 00 
		$a_01_5 = {11 00 28 01 00 00 2b 28 02 00 00 2b 13 00 20 01 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}