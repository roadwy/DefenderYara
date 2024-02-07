
rule Trojan_BAT_AgentTesla_NWO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NWO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_81_0 = {44 37 37 34 5a 34 37 38 56 34 53 37 33 39 32 47 47 42 48 35 34 47 } //01 00  D774Z478V4S7392GGBH54G
		$a_01_1 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}