
rule TrojanDownloader_Win32_Zegost_B{
	meta:
		description = "TrojanDownloader:Win32/Zegost.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 31 2f 6d 75 62 69 61 6f 2e 68 74 6d } //01 00 
		$a_00_1 = {32 30 72 6a 2e } //01 00 
		$a_01_2 = {43 3a 5c 51 51 2e 65 78 65 } //01 00 
		$a_01_3 = {64 30 39 66 32 33 34 30 38 31 38 35 31 31 64 33 39 36 66 36 61 61 66 38 34 34 63 37 65 33 32 35 } //01 00 
		$a_01_4 = {6e 65 74 20 75 73 65 72 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 20 2f 66 75 6c 6c 6e 61 6d 65 } //00 00 
	condition:
		any of ($a_*)
 
}