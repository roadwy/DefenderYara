
rule TrojanClicker_Win32_Klik{
	meta:
		description = "TrojanClicker:Win32/Klik,SIGNATURE_TYPE_PEHSTR_EXT,66 00 66 00 05 00 00 64 00 "
		
	strings :
		$a_02_0 = {54 61 62 4f 72 64 65 72 90 02 03 54 65 78 74 90 02 02 68 74 74 70 3a 2f 2f 90 02 10 75 70 6c 6f 61 64 65 72 90 00 } //01 00 
		$a_00_1 = {73 75 70 65 72 74 64 73 2e 63 6f 6d } //01 00  supertds.com
		$a_00_2 = {6b 6c 69 6b 69 52 61 6e 64 6f 6d 69 7a 65 72 20 3d 20 } //01 00  klikiRandomizer = 
		$a_00_3 = {57 65 62 42 72 6f 77 73 65 72 31 44 6f 77 6e 6c 6f 61 64 43 6f 6d 70 6c 65 74 65 } //01 00  WebBrowser1DownloadComplete
		$a_00_4 = {4b 6c 69 6b 61 74 20 6e 65 20 62 75 64 65 6d 21 20 55 7a 65 20 65 73 74 } //00 00  Klikat ne budem! Uze est
	condition:
		any of ($a_*)
 
}