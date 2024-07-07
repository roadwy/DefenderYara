
rule TrojanDownloader_Win32_Bleyr_A{
	meta:
		description = "TrojanDownloader:Win32/Bleyr.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {8b c8 33 c0 83 e1 03 f3 a4 b9 3f 00 00 00 8d bc 24 90 01 01 00 00 00 f3 ab 66 ab aa 8d 7c 24 10 83 c9 ff 33 c0 f2 ae f7 d1 2b f9 8b c1 8b f7 8b fa 33 d2 c1 e9 02 f3 a5 8b c8 33 c0 83 e1 03 f3 a4 8d bc 24 90 01 01 00 00 00 83 c9 ff f2 ae f7 d1 49 90 00 } //5
		$a_01_1 = {2f 66 20 2f 74 20 2f 69 6d 20 41 59 53 65 72 76 69 63 65 4e 74 2e 61 79 65 } //1 /f /t /im AYServiceNt.aye
		$a_01_2 = {25 73 3f 75 73 65 72 69 64 3d 25 73 26 6d 61 63 3d 25 73 26 76 65 72 3d 25 73 26 6f 73 3d 25 73 26 66 6c 61 67 3d 25 64 } //1 %s?userid=%s&mac=%s&ver=%s&os=%s&flag=%d
		$a_01_3 = {68 74 74 70 3a 2f 2f 68 6f 73 74 00 } //1 瑨灴⼺栯獯t
		$a_01_4 = {68 74 74 70 3a 2f 2f 63 6f 75 6e 74 00 } //1
		$a_01_5 = {00 6e 65 77 64 65 73 6b 32 00 } //1 渀睥敤歳2
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}