
rule Trojan_BAT_AgentTesla_NND_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 09 93 28 90 01 03 0a 1f 21 32 11 08 09 93 28 90 01 03 0a 1f 7e fe 02 16 fe 01 2b 01 16 2c 14 08 09 1f 21 08 09 93 1f 0e 58 1f 5e 5d 58 28 90 01 03 0a 9d 09 17 58 0d 09 07 6f 90 01 03 0a fe 04 2d bd 90 00 } //01 00 
		$a_80_1 = {35 46 47 4a 38 58 52 34 34 47 35 54 46 57 34 41 34 50 41 38 50 } //5FGJ8XR44G5TFW4A4PA8P  01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_80_3 = {53 68 61 72 70 53 74 72 75 63 74 75 72 65 73 2e 53 6f 72 74 69 6e 67 2e 53 6f 72 74 48 65 6c 70 65 72 } //SharpStructures.Sorting.SortHelper  01 00 
		$a_01_4 = {47 65 74 54 79 70 65 } //00 00 
	condition:
		any of ($a_*)
 
}