
rule TrojanDownloader_Win32_Bukvice{
	meta:
		description = "TrojanDownloader:Win32/Bukvice,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_03_0 = {81 ec 00 02 00 00 68 ?? ?? ?? ?? 50 50 8d 44 24 0c 68 ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 8d 44 24 14 83 c4 14 8d 50 01 8a 08 40 84 c9 75 f9 56 2b c2 6a 01 50 8d 4c 24 0c 51 e8 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 83 c4 14 6a 64 ff ?? ?? ?? ?? ?? 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? 68 20 4f 41 00 6a 00 ff ?? ?? ?? ?? ?? 81 c4 00 02 00 00 c3 } //10
		$a_00_1 = {64 65 6c 20 2f 73 20 2f 71 20 22 6b 69 6c 6c 66 69 6c 65 2e 62 61 74 22 } //2 del /s /q "killfile.bat"
		$a_00_2 = {5c 53 65 72 76 69 63 65 44 6f 77 6e 4c 6f 61 64 65 72 2e 69 6e 69 } //2 \ServiceDownLoader.ini
	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=14
 
}