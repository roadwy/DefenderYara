
rule TrojanDownloader_Win32_Small_AAAZ{
	meta:
		description = "TrojanDownloader:Win32/Small.AAAZ,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_00_0 = {25 54 45 4d 50 25 5c 69 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 %TEMP%\iexplorer.exe
		$a_02_1 = {8b d0 59 33 c0 59 85 d2 74 90 01 01 8b fa 83 c9 ff f2 ae f7 d1 49 83 f9 05 72 90 02 07 8d 90 01 01 05 6a 2e 90 00 } //1
		$a_02_2 = {57 57 68 01 02 00 00 50 ff d6 57 57 55 ff 74 24 90 01 01 ff d6 68 90 01 04 57 ff 15 90 01 04 3b c7 74 25 68 90 01 04 57 57 50 ff d3 90 00 } //1
		$a_02_3 = {57 ff d6 83 c4 0c 83 bd 7c ff ff ff 02 0f 85 a5 00 00 00 6a 3f 68 90 01 04 57 ff d6 e9 93 00 00 00 83 f8 0a 75 09 6a 3f 68 90 01 04 eb 7a 83 f8 5a 75 45 6a 3f 68 90 01 04 eb 6c 83 f9 05 75 29 85 c0 75 09 6a 3f 68 90 01 04 eb 5a 83 f8 01 75 09 6a 3f 68 90 01 04 eb 4c 83 f8 02 75 17 6a 3f 68 90 01 04 eb 3e 83 f9 06 75 09 6a 3f 68 90 01 04 eb 30 90 00 } //5
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*5) >=7
 
}