
rule TrojanDownloader_Win32_Regonid_B{
	meta:
		description = "TrojanDownloader:Win32/Regonid.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {76 29 8b d0 2b d1 03 55 14 83 fa 7e 76 03 83 c1 7e 8b 55 08 8a 14 10 2a 55 14 } //1
		$a_01_1 = {3c 41 72 5f 3c 47 73 04 2c 37 eb f0 3c 61 72 53 3c 67 73 04 2c 57 eb e4 } //1
		$a_01_2 = {f7 da 1b d2 81 e2 b7 1d c1 04 03 c0 33 c2 49 75 e7 50 b1 20 89 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_Win32_Regonid_B_2{
	meta:
		description = "TrojanDownloader:Win32/Regonid.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 4f 70 65 6e 42 6c 6f 63 6b 69 6e 67 53 74 72 65 61 6d 41 } //1 URLOpenBlockingStreamA
		$a_01_1 = {00 5c 25 73 25 75 2e 25 73 00 } //1 尀猥甥┮s
		$a_01_2 = {00 69 6e 66 00 64 61 74 00 25 75 00 00 2a 2e 25 73 00 } //1 椀普搀瑡─u⨀┮s
		$a_03_3 = {8b 4d 0c f7 d8 1b c0 83 e0 07 83 c0 06 0f b7 c0 99 6a 00 52 50 e8 ?? ?? ff ff } //1
		$a_00_4 = {6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 63 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 } //1 microsoft corporation
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}