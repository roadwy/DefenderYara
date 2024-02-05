
rule TrojanDownloader_Win32_Frethog_C{
	meta:
		description = "TrojanDownloader:Win32/Frethog.C,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 64 72 69 76 65 72 73 5c 6b 6c 69 66 2e 73 79 73 00 } //02 00 
		$a_00_1 = {4b 61 73 70 65 72 73 6b 79 4c 61 62 5c 70 72 6f 74 65 63 74 65 64 5c 41 56 50 37 5c 70 72 6f 66 69 6c 65 73 5c 55 70 64 61 74 65 72 00 } //03 00 
		$a_00_2 = {41 4e 54 49 56 4d 2e 64 6c 6c 00 4b 41 56 5f 47 6f 75 74 00 53 79 73 44 61 74 61 42 75 66 66 65 72 00 } //02 00 
		$a_03_3 = {6a 08 50 68 73 00 09 00 ff 75 fc ff 15 90 01 02 00 10 85 c0 90 00 } //02 00 
		$a_03_4 = {8d 45 d0 53 50 57 ff 75 08 ff 75 f0 ff 15 90 01 02 00 10 01 7d 08 83 c6 08 ff 4d 0c 75 d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}