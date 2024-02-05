
rule TrojanDropper_Win32_Dogkild_A{
	meta:
		description = "TrojanDropper:Win32/Dogkild.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 64 72 69 76 65 72 73 5c 67 6d 2e 64 6c 73 00 } //01 00 
		$a_01_1 = {63 6d 64 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 65 67 75 69 2e 65 78 65 20 2f 66 } //01 00 
		$a_01_2 = {63 61 63 6c 73 20 25 73 20 2f 65 20 2f 70 20 65 76 65 72 79 6f 6e 65 3a 66 } //01 00 
		$a_01_3 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 20 64 72 6f 71 70 } //02 00 
		$a_01_4 = {66 81 7c 24 10 d7 07 76 } //02 00 
		$a_01_5 = {66 81 7d e0 d7 07 0f 86 } //02 00 
		$a_01_6 = {76 2a 8b 45 fc 53 8a 04 07 fe c0 88 45 0f } //00 00 
	condition:
		any of ($a_*)
 
}