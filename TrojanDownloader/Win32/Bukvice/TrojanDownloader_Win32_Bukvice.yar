
rule TrojanDownloader_Win32_Bukvice{
	meta:
		description = "TrojanDownloader:Win32/Bukvice,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {81 ec 00 02 00 00 68 90 01 04 50 50 8d 44 24 0c 68 90 01 04 50 ff 90 01 05 8d 44 24 14 83 c4 14 8d 50 01 8a 08 40 84 c9 75 f9 56 2b c2 6a 01 50 8d 4c 24 0c 51 e8 90 01 04 56 e8 90 01 04 83 c4 14 6a 64 ff 90 01 05 6a 00 6a 00 6a 00 68 90 01 04 68 20 4f 41 00 6a 00 ff 90 01 05 81 c4 00 02 00 00 c3 90 00 } //02 00 
		$a_00_1 = {64 65 6c 20 2f 73 20 2f 71 20 22 6b 69 6c 6c 66 69 6c 65 2e 62 61 74 22 } //02 00  del /s /q "killfile.bat"
		$a_00_2 = {5c 53 65 72 76 69 63 65 44 6f 77 6e 4c 6f 61 64 65 72 2e 69 6e 69 } //00 00  \ServiceDownLoader.ini
	condition:
		any of ($a_*)
 
}