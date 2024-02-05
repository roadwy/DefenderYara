
rule TrojanDownloader_Win32_Fraudload_H{
	meta:
		description = "TrojanDownloader:Win32/Fraudload.H,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 74 68 65 73 65 6e 68 65 72 50 72 68 62 75 67 67 68 49 73 44 65 8b c4 50 } //01 00 
		$a_01_1 = {83 c4 0c 6a 41 68 63 75 74 65 68 6c 45 78 65 68 53 68 65 6c 8b c4 50 ff 35 } //01 00 
		$a_01_2 = {6a 64 68 46 6f 75 6e 8b c4 68 10 10 00 00 68 1e 30 40 00 50 6a 00 e8 } //01 00 
		$a_01_3 = {57 65 27 72 65 20 70 72 6f 62 61 62 6c 79 20 75 6e 64 65 72 20 57 69 6e 39 38 00 } //01 00 
		$a_01_4 = {4f 70 65 4e 00 47 65 74 54 65 6d 70 50 61 74 68 41 00 50 72 65 73 65 6e 74 00 4e 4f 54 20 46 6f 75 6e 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}