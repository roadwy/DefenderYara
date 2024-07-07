
rule TrojanDownloader_Win32_Ohlat_A{
	meta:
		description = "TrojanDownloader:Win32/Ohlat.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {74 05 83 e8 04 8b 00 8b f0 85 f6 7e 28 bb 01 00 00 00 8d 45 f0 8b 55 fc 0f b6 54 1a ff 2b d3 2b d7 e8 } //1
		$a_01_1 = {5f 6c 6c 65 69 68 42 69 6d 71 6b 7a 00 } //1
		$a_01_2 = {6b 6d 6c 65 41 68 6c 70 6a 79 00 } //1
		$a_01_3 = {70 62 6b 6f 00 } //1
		$a_01_4 = {5c 6c 66 6f 2e 62 61 74 00 } //1
		$a_01_5 = {5c 41 74 61 6c 68 6f 5f 2e 70 69 66 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}