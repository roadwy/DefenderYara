
rule TrojanDownloader_Win32_Yektel_H{
	meta:
		description = "TrojanDownloader:Win32/Yektel.H,SIGNATURE_TYPE_PEHSTR,17 00 17 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00 
		$a_01_1 = {77 73 63 6d 70 2e 64 6c 6c } //01 00 
		$a_01_2 = {5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 64 6f 77 73 5c 72 75 6e } //01 00 
		$a_01_3 = {5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 43 6f 6e 74 72 6f 6c 73 20 46 6f 6c 64 65 72 5c 50 49 44 77 6d 70 } //01 00 
		$a_01_4 = {42 6f 74 20 63 6f 75 6e 74 20 3d } //01 00 
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 69 6e 67 20 74 6f 6f 6c 62 61 72 } //00 00 
	condition:
		any of ($a_*)
 
}