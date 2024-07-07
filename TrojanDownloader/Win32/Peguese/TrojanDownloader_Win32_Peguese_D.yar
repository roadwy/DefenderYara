
rule TrojanDownloader_Win32_Peguese_D{
	meta:
		description = "TrojanDownloader:Win32/Peguese.D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 07 00 00 "
		
	strings :
		$a_01_0 = {8b 85 18 fe ff ff 89 85 1c fe ff ff c6 85 20 fe ff ff 0b 8d 85 1c fe ff ff 50 8d 95 14 fe ff ff b8 } //1
		$a_03_1 = {68 e8 03 00 00 e8 90 01 03 ff 33 c0 55 68 90 01 03 00 64 ff 30 64 89 20 8d 55 94 b8 90 00 } //1
		$a_03_2 = {8d 95 08 fb ff ff b8 90 01 04 e8 90 01 04 8b 85 08 fb ff ff e8 90 01 04 50 6a 00 e8 90 00 } //1
		$a_03_3 = {8d 95 b8 fa ff ff b8 90 01 04 e8 90 01 04 8b 85 b8 fa ff ff e8 90 01 04 50 6a 00 e8 90 01 04 85 c0 76 07 90 00 } //1
		$a_03_4 = {8d 95 f4 fa ff ff b8 90 01 04 e8 90 01 04 8b 85 f4 fa ff ff e8 90 01 04 50 6a 00 e8 90 01 04 85 c0 76 07 90 00 } //1
		$a_03_5 = {8d 95 a8 fa ff ff b8 90 01 04 e8 90 01 04 59 8b 85 a8 fa ff ff e8 90 01 04 50 6a 00 e8 90 00 } //1
		$a_03_6 = {8d 95 e4 fa ff ff b8 90 01 04 e8 90 01 04 59 8b 85 e4 fa ff ff e8 90 01 04 50 6a 00 e8 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1) >=1
 
}