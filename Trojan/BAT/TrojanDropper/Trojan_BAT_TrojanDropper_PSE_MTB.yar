
rule Trojan_BAT_TrojanDropper_PSE_MTB{
	meta:
		description = "Trojan:BAT/TrojanDropper.PSE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 16 9a 28 0e 00 00 0a 28 90 01 03 06 00 28 90 01 03 06 0c 72 90 01 03 70 08 28 90 01 03 0a 28 90 01 03 06 00 72 90 01 03 70 1b 8d 90 01 03 01 13 0b 11 0b 16 72 90 01 03 70 a2 11 0b 17 08 a2 11 0b 18 72 90 01 03 70 a2 11 0b 19 02 16 9a a2 11 0b 1a 72 90 01 03 70 a2 11 0b 28 90 01 03 0a 16 28 90 01 03 06 00 72 90 01 03 70 28 90 01 03 06 00 08 72 90 01 03 70 17 90 00 } //01 00 
		$a_01_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_01_2 = {4c 61 75 6e 63 68 50 72 6f 63 65 73 73 } //00 00  LaunchProcess
	condition:
		any of ($a_*)
 
}