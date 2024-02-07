
rule TrojanDownloader_Win32_Banload_UQ{
	meta:
		description = "TrojanDownloader:Win32/Banload.UQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f8 2b fa 2b 7d 90 01 01 8d 45 90 01 01 8b d7 e8 90 01 04 8d 45 90 01 01 8b 55 90 01 01 e8 90 01 04 43 4e 75 c3 90 00 } //01 00 
		$a_03_1 = {01 75 1a 8d 45 90 01 01 8b 55 90 01 01 8b 92 90 01 04 8b 4d 90 01 01 8b 14 8a 8b 52 90 01 01 e8 90 01 04 83 7d 90 01 01 02 75 2d 90 00 } //01 00 
		$a_03_2 = {75 17 8b 45 90 01 01 8b 80 90 01 04 8b 80 90 01 04 8b 55 90 01 01 8b 08 ff 51 90 01 01 6a 00 6a 00 8b 45 90 01 01 e8 90 01 04 50 8b 45 90 01 01 e8 90 01 04 50 6a 00 e8 90 01 04 68 e8 03 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Banload_UQ_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.UQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 8b 80 18 03 00 00 8b 55 f8 8b 04 90 90 8b 08 8b 45 fc 8b 90 90 20 03 00 00 8d 45 e8 e8 90 01 04 8b 45 e8 e8 90 01 04 50 6a 00 e8 90 00 } //01 00 
		$a_03_1 = {8b 0e 8b 1f 38 d9 75 90 01 01 4a 74 90 01 01 38 fd 75 90 01 01 4a 74 90 01 01 81 e3 00 00 ff 00 81 e1 00 00 ff 00 39 d9 75 90 00 } //01 00 
		$a_01_2 = {5f 5e 5b 59 59 5d c3 00 ff ff ff ff 01 00 00 00 5c 00 00 00 ff ff ff ff 01 00 00 00 53 00 00 00 } //01 00 
		$a_00_3 = {49 45 28 41 4c 28 22 25 73 22 2c 34 29 2c 22 41 4c 28 5c 22 25 30 3a 73 5c 22 2c 33 29 22 2c 22 4a 4b 28 5c 22 25 31 3a 73 5c 22 2c 5c 22 25 30 3a 73 5c 22 29 22 29 } //00 00  IE(AL("%s",4),"AL(\"%0:s\",3)","JK(\"%1:s\",\"%0:s\")")
	condition:
		any of ($a_*)
 
}