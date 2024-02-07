
rule TrojanDownloader_Win32_Tiny_J{
	meta:
		description = "TrojanDownloader:Win32/Tiny.J,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 03 00 "
		
	strings :
		$a_02_0 = {4d 69 63 72 6f 73 6f 66 74 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 00 68 74 74 70 3a 2f 2f 6d 73 69 65 73 65 74 74 69 6e 67 73 2e 63 6f 6d 2f 63 68 65 63 6b 2f 90 02 10 2e 70 68 70 00 68 74 74 70 3a 2f 2f 6d 73 69 65 73 65 74 74 69 6e 67 73 2e 63 6f 6d 2f 63 68 65 63 6b 2f 90 02 10 2e 70 68 70 00 68 74 74 70 3a 2f 2f 6d 73 69 65 73 65 74 74 69 6e 67 73 2e 63 6f 6d 2f 63 68 65 63 6b 2f 90 02 10 2e 70 68 70 3f 72 3d 90 02 04 26 74 73 6b 3d 00 75 70 64 61 74 65 00 2e 65 78 65 00 52 75 6e 4f 6e 63 65 90 01 01 2e 74 5f 5f 00 52 75 6e 4f 6e 63 65 90 01 01 2e 74 6d 70 00 5f 73 76 63 68 6f 73 74 2e 65 78 65 00 20 2d 41 00 63 3a 5c 63 6f 6e 66 2e 6d 79 90 00 } //01 00 
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_2 = {46 75 63 6b 20 79 6f 75 20 53 70 69 6c 62 65 72 67 } //00 00  Fuck you Spilberg
	condition:
		any of ($a_*)
 
}