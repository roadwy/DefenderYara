
rule Trojan_BAT_AgentTesla_LCO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 0a 11 07 11 0b 6f 90 01 03 0a 1d 62 d2 11 07 11 0b 17 d6 6f 90 01 03 0a 1c 62 d2 58 86 11 07 11 0b 18 d6 6f 90 01 03 0a 1b 62 d2 58 86 11 07 11 0b 19 d6 6f 90 00 } //01 00 
		$a_03_1 = {1a 62 d2 58 86 11 07 11 0b 1a d6 6f 90 01 03 0a 19 62 d2 58 86 11 07 11 0b 1b d6 6f 90 01 03 0a 18 62 d2 58 86 11 07 11 0b 1c d6 6f 90 00 } //01 00 
		$a_01_2 = {64 62 33 38 36 31 31 2d 65 39 66 36 2d 34 37 63 64 2d 38 65 32 65 2d 38 36 62 65 62 31 33 33 31 32 } //01 00  db38611-e9f6-47cd-8e2e-86beb13312
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}