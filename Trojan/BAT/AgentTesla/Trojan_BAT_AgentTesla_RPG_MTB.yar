
rule Trojan_BAT_AgentTesla_RPG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {62 00 6d 00 6e 00 2e 00 6c 00 70 00 6d 00 70 00 62 00 61 00 6e 00 74 00 65 00 6e 00 2e 00 69 00 64 00 90 02 40 2e 00 70 00 6e 00 67 00 90 00 } //01 00 
		$a_01_1 = {4b 61 73 70 65 72 73 6b 79 } //01 00  Kaspersky
		$a_01_2 = {41 6e 74 69 2d 56 69 72 75 73 } //01 00  Anti-Virus
		$a_01_3 = {57 65 62 52 65 71 75 65 73 74 } //01 00  WebRequest
		$a_01_4 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_01_5 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_6 = {53 74 72 69 6e 67 } //01 00  String
		$a_01_7 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //00 00  DynamicInvoke
	condition:
		any of ($a_*)
 
}