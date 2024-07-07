
rule TrojanDownloader_Win32_Kuluoz_B{
	meta:
		description = "TrojanDownloader:Win32/Kuluoz.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {33 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a } //1
		$a_01_1 = {2f 69 6e 64 65 78 2e 70 68 70 3f 72 3d 67 61 74 65 26 69 64 3d } //1 /index.php?r=gate&id=
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {26 67 72 6f 75 70 3d 00 26 64 65 62 75 67 3d 00 } //1 朦潲灵=搦扥杵=
		$a_01_4 = {00 69 64 6c 00 72 75 6e 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule TrojanDownloader_Win32_Kuluoz_B_2{
	meta:
		description = "TrojanDownloader:Win32/Kuluoz.B,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b 51 24 03 55 90 01 01 89 55 90 01 01 c6 45 90 01 01 57 c6 45 90 01 01 6f c6 45 90 01 01 72 c6 45 90 01 01 6b c6 45 90 01 01 00 90 00 } //1
		$a_03_1 = {8b 42 24 03 85 90 01 02 ff ff 89 85 90 01 02 ff ff c6 85 90 01 02 ff ff 57 c6 85 90 01 02 ff ff 6f c6 85 90 01 02 ff ff 72 c6 85 90 01 02 ff ff 6b c6 85 90 01 02 ff ff 00 90 00 } //1
		$a_03_2 = {c6 42 01 68 8b 45 90 01 01 03 85 90 01 02 ff ff 8b 4d 90 01 01 89 48 02 8b 55 90 1b 00 03 95 90 1b 01 ff ff c6 42 06 c3 90 00 } //1
		$a_03_3 = {c6 40 01 68 8b 4d 90 01 01 03 8d 90 01 02 ff ff 8b 55 90 01 01 89 51 02 8b 45 90 01 01 03 85 90 01 02 ff ff c6 40 06 c3 90 00 } //1
		$a_01_4 = {2e 70 68 70 3f 72 3d 67 61 74 65 26 69 64 3d } //10 .php?r=gate&id=
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*10) >=11
 
}