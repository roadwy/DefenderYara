
rule TrojanDownloader_Win32_Zlob_KI{
	meta:
		description = "TrojanDownloader:Win32/Zlob.KI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 20 49 4e 53 54 41 4c 4c 41 54 49 4f 4e 3a 20 43 6f 6d 70 6f 6e 65 6e 74 73 20 62 75 6e 64 6c 65 64 20 77 69 74 68 20 6f 75 72 20 73 6f 66 74 77 61 72 65 20 6d 61 79 20 66 65 65 64 20 62 61 63 6b 20 74 6f 20 4c 69 63 65 6e 73 6f 72 } //01 00 
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 57 65 62 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 00 } //01 00 
		$a_01_2 = {5c 62 64 74 62 2e 64 6c 6c 00 } //01 00 
		$a_01_3 = {4e 75 6c 6c 73 6f 66 74 20 49 6e 73 74 61 6c 6c 20 53 79 73 74 65 6d } //00 00 
	condition:
		any of ($a_*)
 
}