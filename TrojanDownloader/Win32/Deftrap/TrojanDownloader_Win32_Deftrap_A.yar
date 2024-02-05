
rule TrojanDownloader_Win32_Deftrap_A{
	meta:
		description = "TrojanDownloader:Win32/Deftrap.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3c 21 44 4f 43 54 59 50 45 00 00 00 72 62 00 00 77 62 00 00 53 76 63 00 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b } //01 00 
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00 
		$a_01_2 = {64 a1 18 00 00 00 8b 40 30 0f b6 40 02 } //00 00 
	condition:
		any of ($a_*)
 
}