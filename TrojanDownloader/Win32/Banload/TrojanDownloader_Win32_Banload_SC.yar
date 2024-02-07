
rule TrojanDownloader_Win32_Banload_SC{
	meta:
		description = "TrojanDownloader:Win32/Banload.SC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 7c 30 ff 8b 45 e0 0f b6 00 89 45 f4 8b 45 dc e8 90 01 04 40 50 8d 45 dc b9 01 00 00 00 8b 15 90 01 04 e8 90 00 } //01 00 
		$a_02_1 = {c2 08 00 53 a1 90 01 04 83 38 00 74 90 01 01 8b 1d 90 01 04 8b 1b ff d3 5b c3 90 01 01 55 8b ec 51 53 56 57 89 4d fc 8b da 8b f0 8b c3 ff 50 f4 90 00 } //01 00 
		$a_00_2 = {49 45 28 41 4c 28 22 25 73 22 2c 34 29 2c 22 41 4c 28 5c 22 25 30 3a 73 5c 22 2c 33 29 22 2c 22 4a 4b 28 5c 22 25 31 3a 73 5c 22 2c 5c 22 25 30 3a 73 5c 22 29 22 29 } //01 00  IE(AL("%s",4),"AL(\"%0:s\",3)","JK(\"%1:s\",\"%0:s\")")
		$a_00_3 = {ff ff ff ff 03 00 00 00 d4 e0 e0 00 ff ff ff ff 04 00 00 00 dc a6 9b 9b 00 00 00 00 ff ff ff ff 03 00 00 00 e3 e3 e3 00 ff ff ff ff 02 00 00 00 9a e3 } //00 00 
	condition:
		any of ($a_*)
 
}