
rule TrojanDownloader_Win32_Fraudload_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Fraudload.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_02_0 = {83 c4 10 6a 00 68 80 00 00 00 6a 02 6a 00 6a 00 68 00 00 00 c0 8d 85 b0 f1 ff ff 50 ff 15 ?? ?? ?? ?? 89 85 58 ef ff ff 6a 00 8d 8d fc fd ff ff 51 8b 95 ac f1 ff ff 52 8b 85 c0 f3 ff ff 03 85 b8 f3 ff ff 50 8b 8d 58 ef ff ff 51 ff 15 ?? ?? ?? ?? 8b 95 58 ef ff ff 52 ff 15 ?? ?? ?? ?? 8b 85 b8 f3 ff ff 03 85 ac f1 ff ff 89 85 b8 f3 ff ff e9 f2 fe ff ff 68 ?? ?? ?? ?? 8d 8d c8 f5 ff ff 51 68 ?? ?? ?? ?? 8d 95 c8 f9 ff ff 52 ff 15 ?? ?? ?? ?? 83 c4 10 6a 05 8d 85 c8 f9 ff ff 50 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? b8 df 0a 00 00 8b e5 5d c2 04 00 } //1
		$a_00_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 25 73 5c 25 73 2e 6c 69 63 } //1 C:\Program Files\%s\%s.lic
		$a_00_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 25 73 5c 25 73 2e 65 78 65 } //1 C:\Program Files\%s\%s.exe
		$a_01_3 = {50 72 6f 78 79 53 65 72 76 65 72 00 50 72 6f 78 79 45 6e 61 62 6c 65 } //1
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 } //1 Software\Microsoft\Windows\CurrentVersion\Internet Settings
		$a_01_5 = {41 6e 74 69 53 70 79 77 61 72 65 53 68 69 65 6c 64 } //1 AntiSpywareShield
		$a_01_6 = {68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 25 73 2e 63 6f 6d } //1 http://download.%s.com
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}