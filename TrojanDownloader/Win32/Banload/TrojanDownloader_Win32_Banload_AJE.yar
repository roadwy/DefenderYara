
rule TrojanDownloader_Win32_Banload_AJE{
	meta:
		description = "TrojanDownloader:Win32/Banload.AJE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 69 00 20 00 74 00 68 00 65 00 72 00 65 00 20 00 68 00 61 00 63 00 6b 00 65 00 72 00 73 00 0d 00 0d 00 0d 00 68 00 61 00 63 00 6b 00 69 00 6e 00 67 00 20 00 69 00 73 00 20 00 66 00 75 00 6e 00 21 00 } //01 00 
		$a_01_1 = {63 00 3a 00 5c 00 77 00 69 00 6e 00 73 00 79 00 73 00 5c 00 77 00 6e 00 65 00 2e 00 65 00 78 00 65 00 } //01 00  c:\winsys\wne.exe
		$a_01_2 = {47 61 6d 65 20 2d 20 4f 76 65 72 64 75 65 20 4c 6f 61 6e 73 20 2d } //00 00  Game - Overdue Loans -
	condition:
		any of ($a_*)
 
}