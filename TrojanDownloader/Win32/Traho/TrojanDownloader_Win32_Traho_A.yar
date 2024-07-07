
rule TrojanDownloader_Win32_Traho_A{
	meta:
		description = "TrojanDownloader:Win32/Traho.A,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_02_0 = {00 68 74 74 70 3a 2f 2f 73 70 6f 72 74 73 2e 79 61 68 6f 6f 35 35 30 2e 63 6f 6d 2f 69 6d 61 67 65 2f 6c 6f 67 6f 2e 6a 70 67 3f 71 75 65 72 79 69 64 3d 38 30 90 01 03 00 90 00 } //10
		$a_00_1 = {5c 74 65 6d 70 61 71 } //1 \tempaq
		$a_00_2 = {00 25 73 25 73 25 73 25 73 25 73 3f 71 75 65 72 79 69 64 3d 25 73 00 } //1
		$a_00_3 = {48 54 54 50 2f 31 2e 30 } //1 HTTP/1.0
		$a_00_4 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
		$a_00_5 = {49 6e 74 65 72 6e 65 74 51 75 65 72 79 44 61 74 61 41 76 61 69 6c 61 62 6c 65 } //1 InternetQueryDataAvailable
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=15
 
}