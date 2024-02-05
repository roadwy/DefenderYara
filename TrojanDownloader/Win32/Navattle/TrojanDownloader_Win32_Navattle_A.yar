
rule TrojanDownloader_Win32_Navattle_A{
	meta:
		description = "TrojanDownloader:Win32/Navattle.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 42 61 74 74 6c 65 2e 6e 65 74 00 00 43 6f 6e 73 65 6e 74 50 72 6f 6d 70 74 42 65 68 61 76 69 6f 72 41 64 6d 69 6e } //01 00 
		$a_01_1 = {2e 6e 61 76 65 72 2e 63 6f 6d 2f 00 00 00 49 64 65 6e 74 69 74 79 } //01 00 
		$a_01_2 = {68 74 74 70 3a 2f 2f 00 2e 65 78 65 00 00 00 00 2e 67 69 66 00 00 00 00 52 75 6e 61 73 } //01 00 
		$a_01_3 = {5c 52 75 6e 00 00 00 6e 75 73 62 33 6d 6f 6e 2e 65 78 65 } //01 00 
		$a_01_4 = {8a 55 f8 88 11 8b 45 f4 83 c0 01 89 45 f4 8b 4d fc 83 c1 03 89 4d fc eb a2 } //00 00 
		$a_00_5 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}