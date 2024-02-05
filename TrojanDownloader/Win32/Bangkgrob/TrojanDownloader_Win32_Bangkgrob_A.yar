
rule TrojanDownloader_Win32_Bangkgrob_A{
	meta:
		description = "TrojanDownloader:Win32/Bangkgrob.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 04 00 "
		
	strings :
		$a_01_0 = {70 3a 2f 2f 66 69 74 61 70 72 65 74 61 2e 63 6f 6d } //04 00 
		$a_01_1 = {69 6e 64 65 78 2e 70 68 70 2f 64 6f 77 6e 6c 6f 61 64 63 6f 75 6e 74 2f 66 75 67 69 74 69 76 6f 2d 31 30 30 } //04 00 
		$a_01_2 = {77 2e 74 72 61 6a 61 6e 6f 61 6c 6d 65 69 64 61 2e 63 6f 6d 2e 62 72 } //02 00 
		$a_01_3 = {2f 43 6c 69 65 6e 74 65 73 2f 49 6e 73 74 61 6c 2e 62 63 6b } //01 00 
		$a_01_4 = {2f 6f 6c 64 2e 62 63 6b } //01 00 
		$a_01_5 = {2f 76 69 73 74 61 2e 62 63 6b } //01 00 
		$a_01_6 = {2f 54 61 73 6b 2e 62 63 6b } //01 00 
		$a_01_7 = {2f 78 70 2e 62 63 6b } //00 00 
		$a_00_8 = {5d 04 00 00 bc } //30 03 
	condition:
		any of ($a_*)
 
}