
rule TrojanDownloader_Win32_Forpi_B{
	meta:
		description = "TrojanDownloader:Win32/Forpi.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 75 00 2e 00 70 00 70 00 74 00 76 00 37 00 2e 00 63 00 6f 00 6d 00 2f 00 74 00 6a 00 31 00 2f 00 } //1 http://u.pptv7.com/tj1/
		$a_01_1 = {63 6c 73 57 61 69 74 61 62 6c 65 54 69 6d 65 72 } //1 clsWaitableTimer
		$a_03_2 = {50 f3 ab b9 4a 00 00 00 8d bc 24 90 01 02 00 00 f3 ab b9 4a 00 00 00 8d 7c 24 14 f3 ab 6a 0f e8 90 00 } //1
		$a_03_3 = {50 6a 00 8d 45 d4 52 50 ff d6 8b 4d dc 50 8d 55 d8 51 52 ff d6 50 53 e8 90 01 02 ff ff 90 00 } //1
		$a_00_4 = {74 00 6a 00 2e 00 77 00 61 00 6e 00 6c 00 65 00 69 00 73 00 68 00 69 00 2e 00 63 00 6f 00 6d 00 } //1 tj.wanleishi.com
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}