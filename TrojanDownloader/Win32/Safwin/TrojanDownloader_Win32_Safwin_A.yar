
rule TrojanDownloader_Win32_Safwin_A{
	meta:
		description = "TrojanDownloader:Win32/Safwin.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {3a 5c 57 69 6e 53 61 66 65 5c 4b 75 61 69 5a 69 70 5f 53 65 74 75 70 5f 90 02 0a 2e 65 78 65 90 00 } //01 00 
		$a_00_1 = {3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 33 36 30 5c 33 36 30 53 61 66 65 } //01 00  :\Program Files\360\360Safe
		$a_02_2 = {68 74 74 70 3a 2f 2f 76 69 70 2e 90 02 0a 2e 63 6f 6d 3a 39 39 39 39 2f 53 75 62 6d 69 74 2e 70 68 70 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}