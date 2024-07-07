
rule TrojanDownloader_Win32_Small_AHQ{
	meta:
		description = "TrojanDownloader:Win32/Small.AHQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 73 3f 6d 61 63 3d 25 73 26 76 65 72 3d 25 73 26 6f 73 3d 57 69 6e 58 50 26 69 70 3d 25 73 } //1 %s?mac=%s&ver=%s&os=WinXP&ip=%s
		$a_01_1 = {58 39 36 33 41 37 38 46 30 30 30 30 2d 44 42 43 39 2d 32 64 31 31 2d 37 30 37 42 2d 42 41 33 54 46 4f 53 } //1 X963A78F0000-DBC9-2d11-707B-BA3TFOS
		$a_03_2 = {5c 4e 65 74 4d 65 65 90 01 01 69 6e 67 5c 55 6e 69 6e 90 01 01 74 61 6c 6c 2e 65 78 65 90 00 } //1
		$a_03_3 = {69 75 75 71 3b 30 30 90 02 03 2f 79 79 38 2f 6a 6f 30 90 02 03 30 64 70 76 6f 75 2f 62 74 71 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}