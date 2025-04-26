
rule TrojanDownloader_Win32_Chasendi_A{
	meta:
		description = "TrojanDownloader:Win32/Chasendi.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_00_0 = {73 65 74 75 70 5f 25 58 2e 25 73 } //1 setup_%X.%s
		$a_00_1 = {2f 77 69 6e 5f 73 65 74 75 70 2e 64 61 74 } //1 /win_setup.dat
		$a_00_2 = {6b 61 6b 61 5f 75 72 6c } //1 kaka_url
		$a_00_3 = {6e 65 77 74 61 62 2e 6b 61 6b 61 } //1 newtab.kaka
		$a_01_4 = {62 69 74 73 5f 64 6f 6d 61 69 6e 73 } //1 bits_domains
		$a_00_5 = {72 69 79 61 68 2e 6e 65 74 3b 7a 61 6d 62 69 2e 69 6e 66 6f 3b 6c 65 6e 64 61 2e 69 6e 66 6f 3b 61 6d 6f 75 73 2e 6e 65 74 } //1 riyah.net;zambi.info;lenda.info;amous.net
		$a_00_6 = {38 32 2e 31 36 33 2e 31 34 33 2e 31 37 36 3b 38 32 2e 31 36 33 2e 31 34 32 2e 31 37 38 } //1 82.163.143.176;82.163.142.178
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=4
 
}
rule TrojanDownloader_Win32_Chasendi_A_2{
	meta:
		description = "TrojanDownloader:Win32/Chasendi.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_03_0 = {23 7d d0 89 c8 c1 e8 03 32 1c 3a ba 19 86 61 18 f7 e2 d1 ea 69 c2 a8 00 00 00 f7 d8 02 9c 01 ?? ?? ?? ?? 88 1e 46 3b 75 d8 0f 82 b6 ff ff ff } //1
		$a_03_1 = {0f 85 14 ff ff ff 8b 55 d4 8d 4a 01 8d 04 c9 89 cf 8d 04 40 8b 84 02 ?? ?? ?? ?? 85 c0 0f 85 77 fe ff ff } //1
		$a_01_2 = {88 1e 46 3b 75 d8 0f 82 c4 ff ff ff e9 69 00 00 00 } //1
		$a_03_3 = {8d 3c 39 8b 5d cc 23 7d d8 2a 14 3b 89 f3 8b 7d d4 29 cb 0f b6 ca 0f b7 8c 09 ?? ?? ?? ?? 01 cb 88 18 40 89 f3 39 f8 0f } //1
		$a_03_4 = {0f b6 08 89 da 29 c2 0f b7 8c 09 ?? ?? ?? ?? 01 ca 88 10 40 39 f8 0f 82 e4 ff ff ff e9 62 00 00 00 } //1
		$a_03_5 = {3d 87 1c 00 00 89 45 e4 0f 85 2b ff ff ff 8b 55 e0 8d 4a 01 8d 04 c9 89 cf 8d 04 40 8b 84 02 ?? ?? ?? ?? 85 c0 0f 85 be fe ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=3
 
}