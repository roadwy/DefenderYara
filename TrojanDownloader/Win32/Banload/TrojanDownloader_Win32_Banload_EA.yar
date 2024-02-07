
rule TrojanDownloader_Win32_Banload_EA{
	meta:
		description = "TrojanDownloader:Win32/Banload.EA,SIGNATURE_TYPE_PEHSTR_EXT,6a 00 6a 00 08 00 00 32 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //32 00  SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_00_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 49 73 61 73 73 2e 73 63 72 } //01 00  C:\WINDOWS\SYSTEM32\Isass.scr
		$a_00_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 63 73 72 73 2e 73 63 72 } //01 00  C:\WINDOWS\SYSTEM32\csrs.scr
		$a_02_4 = {68 74 74 70 3a 2f 2f 90 02 20 2f 49 73 61 73 73 2e 6a 70 67 90 00 } //01 00 
		$a_02_5 = {68 74 74 70 3a 2f 2f 90 02 20 2f 63 73 72 73 2e 6a 70 67 90 00 } //01 00 
		$a_00_6 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 55 70 64 61 74 65 } //01 00  C:\WINDOWS\SYSTEM32\Update
		$a_02_7 = {6a 00 6a 00 8d 45 e8 b9 90 01 04 8b 15 90 01 04 e8 90 01 04 8b 45 e8 e8 90 01 04 50 a1 90 01 04 e8 90 01 04 50 6a 00 e8 90 01 04 8d 45 e4 b9 90 01 04 8b 15 90 01 04 e8 90 01 04 8b 45 e4 50 8d 45 e0 b9 90 01 04 8b 15 90 01 04 e8 90 01 04 8b 45 e0 5a e8 90 01 04 8d 45 dc b9 90 01 04 8b 15 90 01 04 e8 90 01 04 8b 45 dc 33 d2 e8 90 01 04 b8 90 01 04 ba 90 01 04 e8 90 01 04 6a 00 6a 00 8d 45 d8 b9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}