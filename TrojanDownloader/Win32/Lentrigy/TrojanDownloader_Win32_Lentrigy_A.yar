
rule TrojanDownloader_Win32_Lentrigy_A{
	meta:
		description = "TrojanDownloader:Win32/Lentrigy.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_03_0 = {42 8a 0a 84 c9 75 f6 90 09 03 00 80 2a 90 00 } //1
		$a_03_1 = {ff 30 d0 8b 55 f4 88 04 90 01 01 89 90 00 } //1
		$a_01_2 = {8b 54 24 04 8a 04 02 88 44 1e ff 39 df 7f d8 } //1
		$a_03_3 = {ff 30 c1 8b 55 90 01 01 8b 45 90 01 01 88 0c 02 90 00 } //1
		$a_03_4 = {0f b6 00 83 e8 90 01 01 8b 55 08 88 02 ff 45 08 8b 45 08 8a 00 84 c0 75 e6 90 00 } //1
		$a_03_5 = {ff 30 d0 8b 90 01 03 ff ff 8b 90 01 03 ff ff 88 04 11 8b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=2
 
}