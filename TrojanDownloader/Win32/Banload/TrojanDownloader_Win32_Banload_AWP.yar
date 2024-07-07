
rule TrojanDownloader_Win32_Banload_AWP{
	meta:
		description = "TrojanDownloader:Win32/Banload.AWP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 70 ff d7 8b d0 8d 4d cc ff d6 50 ff d3 8b d0 8d 4d c8 ff d6 50 6a 3a ff d7 8b d0 8d 4d c4 ff d6 50 ff d3 8b d0 8d 4d c0 ff d6 50 6a 2f ff d7 8b d0 8d 4d bc ff d6 50 ff d3 8b d0 8d 4d b8 ff d6 50 6a 2f ff d7 8b d0 8d 4d b4 ff d6 50 ff d3 8b d0 8d 4d b0 ff d6 50 6a 77 } //1
		$a_03_1 = {6a 2e ff d7 8b d0 8d 8d 90 01 02 ff ff ff d6 50 ff d3 8b d0 8d 8d 90 01 02 ff ff ff d6 50 6a 90 03 01 01 6a 67 ff d7 8b d0 8d 8d 90 01 02 ff ff ff d6 50 ff d3 8b d0 8d 8d 90 01 02 ff ff ff d6 50 6a 90 03 01 01 70 69 ff d7 8b d0 8d 8d 90 01 02 ff ff ff d6 50 ff d3 8b d0 8d 8d 90 01 02 ff ff ff d6 50 6a 90 03 01 01 67 66 90 00 } //1
		$a_01_2 = {6a 74 ff d7 8b d0 8d 4d 9c ff d6 50 ff d3 8b d0 8d 4d 98 ff d6 50 6a 2e ff d7 8b d0 8d 4d 94 ff d6 50 ff d3 8b d0 8d 4d 90 ff d6 50 6a 6c ff d7 8b d0 8d 4d 8c ff d6 50 ff d3 8b d0 8d 4d 88 ff d6 50 6a 79 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}