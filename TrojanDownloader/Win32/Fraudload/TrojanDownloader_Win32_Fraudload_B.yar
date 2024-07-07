
rule TrojanDownloader_Win32_Fraudload_B{
	meta:
		description = "TrojanDownloader:Win32/Fraudload.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_02_0 = {83 c4 10 6a 00 68 80 00 00 00 6a 02 6a 00 6a 00 68 00 00 00 c0 8d 85 b0 f1 ff ff 50 ff 15 90 01 04 89 85 58 ef ff ff 6a 00 8d 8d fc fd ff ff 51 8b 95 ac f1 ff ff 52 8b 85 c0 f3 ff ff 03 85 b8 f3 ff ff 50 8b 8d 58 ef ff ff 51 ff 15 90 01 04 8b 95 58 ef ff ff 52 ff 15 90 01 04 8b 85 b8 f3 ff ff 03 85 ac f1 ff ff 89 85 b8 f3 ff ff e9 f2 fe ff ff 68 90 01 04 8d 8d c8 f5 ff ff 51 68 90 01 04 8d 95 c8 f9 ff ff 52 ff 15 90 01 04 83 c4 10 6a 05 8d 85 c8 f9 ff ff 50 ff 15 90 01 04 6a 00 ff 15 90 01 04 b8 df 0a 00 00 8b e5 5d c2 04 00 90 00 } //1
		$a_00_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 25 73 5c 25 73 2e 6c 69 63 } //1 C:\Program Files\%s\%s.lic
		$a_00_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 25 73 5c 25 73 2e 65 78 65 } //1 C:\Program Files\%s\%s.exe
		$a_02_3 = {25 73 20 2f 90 02 10 2e 70 68 70 3f 26 25 73 90 01 08 26 75 3d 25 75 26 70 3d 25 75 20 25 73 90 02 20 2e 63 6f 6d 90 00 } //1
		$a_01_4 = {25 73 43 61 63 68 65 2d 43 6f 6e 74 72 6f 6c 3a 20 6e 6f 2d 63 61 63 68 65 0d 25 73 0d 25 73 } //1
		$a_02_5 = {25 73 20 68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 25 73 2e 63 6f 6d 2f 90 02 10 2e 70 68 70 3f 25 73 90 01 08 26 75 3d 25 75 26 70 3d 25 75 20 25 73 90 02 20 2e 63 6f 6d 90 00 } //1
		$a_01_6 = {50 72 6f 78 79 53 65 72 76 65 72 00 50 72 6f 78 79 45 6e 61 62 6c 65 } //1
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 } //1 Software\Microsoft\Windows\CurrentVersion\Internet Settings
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_01_4  & 1)*1+(#a_02_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}