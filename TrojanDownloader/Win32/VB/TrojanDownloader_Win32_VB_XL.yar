
rule TrojanDownloader_Win32_VB_XL{
	meta:
		description = "TrojanDownloader:Win32/VB.XL,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 44 00 6f 00 6b 00 75 00 6d 00 65 00 6e 00 74 00 65 00 20 00 75 00 6e 00 64 00 20 00 45 00 69 00 6e 00 73 00 74 00 65 00 6c 00 6c 00 75 00 6e 00 67 00 65 00 6e 00 5c 00 4c 00 6f 00 63 00 6f 00 73 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 45 00 61 00 73 00 79 00 20 00 4c 00 6f 00 61 00 64 00 20 00 50 00 72 00 69 00 76 00 61 00 74 00 65 00 } //01 00  C:\Dokumente und Einstellungen\Locos\Desktop\Easy Load Private
		$a_01_1 = {43 00 68 00 65 00 63 00 6b 00 20 00 75 00 72 00 20 00 55 00 52 00 4c 00 } //01 00  Check ur URL
		$a_01_2 = {59 00 6f 00 75 00 20 00 63 00 61 00 6e 00 20 00 6f 00 6e 00 6c 00 79 00 20 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 2e 00 65 00 78 00 65 00 20 00 46 00 69 00 6c 00 65 00 73 00 21 00 } //01 00  You can only Download .exe Files!
		$a_01_3 = {44 00 72 00 6f 00 70 00 2e 00 65 00 78 00 65 00 } //01 00  Drop.exe
		$a_01_4 = {55 00 52 00 4c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 54 00 6f 00 46 00 69 00 6c 00 65 00 41 00 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}