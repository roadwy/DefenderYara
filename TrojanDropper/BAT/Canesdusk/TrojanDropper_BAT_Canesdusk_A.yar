
rule TrojanDropper_BAT_Canesdusk_A{
	meta:
		description = "TrojanDropper:BAT/Canesdusk.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0c 02 02 8e b7 17 da 91 1f 70 61 0d 02 8e b7 17 d6 8d 1b 00 00 01 0b 16 02 8e b7 17 da 13 06 13 05 2b 2d 07 11 05 02 11 05 91 09 61 08 11 04 } //01 00 
		$a_01_1 = {64 65 63 72 79 70 74 00 6d 65 73 73 61 67 65 00 70 61 73 73 77 6f 72 64 } //00 00 
	condition:
		any of ($a_*)
 
}