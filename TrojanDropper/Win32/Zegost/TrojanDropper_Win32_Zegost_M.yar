
rule TrojanDropper_Win32_Zegost_M{
	meta:
		description = "TrojanDropper:Win32/Zegost.M,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {47 68 30 73 74 20 55 70 64 61 74 65 00 } //01 00 
		$a_00_1 = {6e 65 74 73 76 63 73 5f 30 78 25 64 00 } //01 00 
		$a_03_2 = {2e 50 41 44 90 02 07 44 4c 4c 00 42 49 4e 00 53 65 72 76 69 63 65 90 00 } //01 00 
		$a_02_3 = {43 72 65 61 74 65 53 65 72 76 69 63 65 28 50 61 72 61 6d 65 74 65 72 73 29 90 02 07 25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 90 00 } //02 00 
		$a_03_4 = {68 ff 01 0f 00 90 01 02 53 90 02 03 ff 15 90 01 04 8b d8 3b 90 01 01 89 5d 90 01 01 75 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}