
rule TrojanDownloader_Win32_Cbeplay_Q{
	meta:
		description = "TrojanDownloader:Win32/Cbeplay.Q,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {b9 4d 5a 00 00 8b 45 08 66 39 08 } //01 00 
		$a_03_1 = {74 69 8b 44 24 14 8d 54 24 0c 52 68 90 01 04 50 57 56 68 02 01 00 00 c7 44 24 24 00 00 00 00 90 00 } //01 00 
		$a_02_2 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 90 02 05 73 76 63 68 6f 73 74 2e 65 78 65 90 00 } //01 00 
		$a_01_3 = {53 41 4d 50 4c 45 00 00 56 58 00 00 56 49 52 55 53 00 } //00 00 
	condition:
		any of ($a_*)
 
}