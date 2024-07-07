
rule TrojanDownloader_Win32_Nymaim_G{
	meta:
		description = "TrojanDownloader:Win32/Nymaim.G,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc d1 f8 8b 4d 08 0f be 04 01 0f b6 4d 0c 33 c1 8b 4d f8 88 01 } //1
		$a_03_1 = {83 c4 01 68 90 01 04 58 83 ec fd 50 c3 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_Win32_Nymaim_G_2{
	meta:
		description = "TrojanDownloader:Win32/Nymaim.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 00 88 45 90 01 01 8b 45 90 01 01 25 ff 00 00 00 88 45 90 01 01 ff 75 90 01 01 ff 75 90 01 01 e8 90 01 02 ff ff 59 59 8b 4d 90 01 01 03 4d 90 01 01 88 01 90 00 } //1
		$a_03_1 = {ff 75 08 c3 90 09 0c 00 8d 15 90 01 04 52 68 90 00 } //1
		$a_03_2 = {ff ff 59 59 68 90 01 04 e8 90 01 01 ff ff ff 90 09 0f 00 ff 90 01 01 68 90 01 04 68 90 01 04 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}