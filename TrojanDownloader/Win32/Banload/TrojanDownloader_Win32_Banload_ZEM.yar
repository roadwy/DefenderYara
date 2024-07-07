
rule TrojanDownloader_Win32_Banload_ZEM{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZEM,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {3c 4d 75 07 80 fb 48 75 02 b0 4e 8b d8 25 ff 00 00 00 83 c0 de 83 f8 38 0f 87 90 01 04 8a 80 90 01 04 ff 24 85 90 00 } //2
		$a_03_1 = {8b 0e 8b 1f 38 d9 75 90 01 01 4a 74 90 01 01 38 fd 75 90 01 01 4a 74 90 01 01 81 e3 00 00 ff 00 81 e1 00 00 ff 00 39 d9 75 90 00 } //2
		$a_00_2 = {49 45 28 41 4c 28 22 25 73 22 2c 34 29 2c 22 41 4c 28 5c 22 25 30 3a 73 5c 22 2c 33 29 22 2c 22 4a 4b 28 5c 22 25 31 3a 73 5c 22 2c 5c 22 25 30 3a 73 5c 22 29 22 29 } //2 IE(AL("%s",4),"AL(\"%0:s\",3)","JK(\"%1:s\",\"%0:s\")")
		$a_01_3 = {73 69 62 63 64 62 2e 6a 70 67 } //1 sibcdb.jpg
		$a_01_4 = {72 61 64 69 6f 74 61 78 62 73 } //1 radiotaxbs
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_00_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}