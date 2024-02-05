
rule TrojanDownloader_Win32_Adclick{
	meta:
		description = "TrojanDownloader:Win32/Adclick,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {6d 69 63 72 6f 73 6f 66 74 2e 6c 6f 67 69 6e 61 70 70 2e 63 6f 6d 2f 75 70 64 61 74 65 } //02 00 
		$a_01_1 = {63 6e 74 2e 61 64 68 61 72 75 2e 63 6f 6d 2f 61 64 75 6c 74 2e 70 68 70 3f 63 70 69 64 3d 6e 76 00 53 6f 66 74 77 61 72 65 5c 00 00 00 6f 70 65 6e } //01 00 
		$a_01_2 = {25 25 57 49 4e 44 4f 57 53 5c 25 73 70 72 76 2e 69 6d 62 } //01 00 
		$a_01_3 = {25 41 46 46 49 4c 44 41 54 41 00 00 43 6c 69 63 6b 55 72 6c } //01 00 
		$a_01_4 = {00 63 6c 69 63 6b 63 79 63 6c 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}