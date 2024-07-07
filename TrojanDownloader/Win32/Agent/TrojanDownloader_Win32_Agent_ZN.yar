
rule TrojanDownloader_Win32_Agent_ZN{
	meta:
		description = "TrojanDownloader:Win32/Agent.ZN,SIGNATURE_TYPE_PEHSTR_EXT,6a 00 69 00 06 00 00 "
		
	strings :
		$a_02_0 = {7b 33 34 46 36 37 33 45 90 01 01 2d 38 37 38 46 2d 31 31 44 35 2d 42 39 38 41 2d 41 30 42 30 44 30 37 42 38 43 37 43 7d 90 00 } //100
		$a_00_1 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72 } //1 Internet Explorer_Server
		$a_00_2 = {48 57 4e 44 20 3a 25 6c 64 } //1 HWND :%ld
		$a_00_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 79 66 69 6c 65 64 69 73 74 72 69 62 75 74 69 6f 6e 2e 63 6f 6d 2f 6d 66 64 2e 70 68 70 } //1 http://www.myfiledistribution.com/mfd.php
		$a_00_4 = {49 45 4c 69 74 65 20 76 65 72 3a 30 2e 30 2e 30 } //1 IELite ver:0.0.0
		$a_00_5 = {a1 54 b1 00 10 8b 0d 58 b1 00 10 66 8b 15 5c b1 00 10 89 84 24 50 01 00 00 89 8c 24 54 01 00 00 b9 3e 00 00 00 33 c0 8d bc 24 5a 01 00 00 66 89 94 24 58 01 00 00 be bc b1 00 10 f3 ab 66 ab b9 0a 00 00 00 8d bc 24 ec 00 00 00 f3 a5 66 a5 b9 0e 00 00 00 33 c0 8d bc 24 16 01 00 00 f3 ab 66 ab e8 } //2
	condition:
		((#a_02_0  & 1)*100+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*2) >=105
 
}