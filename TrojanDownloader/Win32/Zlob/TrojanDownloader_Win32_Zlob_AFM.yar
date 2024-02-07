
rule TrojanDownloader_Win32_Zlob_AFM{
	meta:
		description = "TrojanDownloader:Win32/Zlob.AFM,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c 7b } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{
		$a_01_1 = {25 73 2f 69 6e 73 74 2f 69 6e 64 65 78 2e 70 68 70 3f 61 66 66 69 64 3d 25 73 26 73 75 62 69 64 3d 25 73 26 67 75 69 64 3d 25 73 26 76 65 72 3d 25 73 26 6b 65 79 3d 25 73 } //01 00  %s/inst/index.php?affid=%s&subid=%s&guid=%s&ver=%s&key=%s
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 43 4d 56 69 64 65 6f 50 6c 75 67 69 6e } //01 00  SOFTWARE\CMVideoPlugin
		$a_01_3 = {76 00 69 00 72 00 75 00 73 00 61 00 6c 00 65 00 72 00 74 00 75 00 72 00 6c 00 } //01 00  virusalerturl
		$a_01_4 = {43 4d 56 69 64 65 6f 2e 44 4c 4c } //00 00  CMVideo.DLL
	condition:
		any of ($a_*)
 
}