
rule TrojanDownloader_Win32_Banload_AQN{
	meta:
		description = "TrojanDownloader:Win32/Banload.AQN,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1e 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b d0 83 e2 03 8a 92 ?? ?? 40 00 30 14 08 40 3b c6 7c ed c3 } //1
		$a_01_1 = {ff d5 eb 3b 33 ff 8d 9b 00 00 00 00 8b 4c fc 10 51 56 ff d3 89 44 fc 14 85 c0 74 e3 47 83 ff 03 7c ea 8b 54 24 14 } //1
		$a_01_2 = {09 08 48 75 6a 21 4c 11 3b 03 56 31 3b 04 4b 2a 31 09 00 00 09 08 48 75 6a 35 5a 35 3b 15 4b } //10
		$a_01_3 = {09 08 48 75 6a 35 5a 35 3b 15 4b 14 31 10 09 77 18 14 6d 26 3a 0e 4d 26 3d 13 56 2c 30 } //10
		$a_01_4 = {29 10 48 6d 37 17 5c 26 30 13 5a 31 70 06 4b } //10
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10) >=30
 
}