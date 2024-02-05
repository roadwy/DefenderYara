
rule TrojanDropper_BAT_Agent_E{
	meta:
		description = "TrojanDropper:BAT/Agent.E,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {61 6e 74 69 53 61 6e 64 62 6f 78 69 65 } //03 00 
		$a_01_1 = {64 69 73 61 62 6c 65 57 65 62 73 69 74 65 42 6c 6f 63 6b 65 72 } //03 00 
		$a_01_2 = {66 61 6b 65 45 72 72 6f 72 4d 65 73 73 61 67 65 } //03 00 
		$a_01_3 = {22 00 20 00 67 00 6f 00 74 00 6f 00 20 00 52 00 65 00 70 00 65 00 61 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}