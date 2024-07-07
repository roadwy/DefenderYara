
rule TrojanDownloader_Win32_Bulilit_D{
	meta:
		description = "TrojanDownloader:Win32/Bulilit.D,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0c 00 08 00 00 "
		
	strings :
		$a_01_0 = {68 01 00 01 00 68 31 0d 01 06 68 32 0d 01 52 } //4
		$a_01_1 = {8d 55 e8 68 00 00 00 20 8d 45 e4 52 8d 4d c4 50 8d 55 08 51 8d 45 e0 52 8b 55 ec 8d 4d d8 50 51 52 e8 } //4
		$a_01_2 = {77 2e 64 79 77 74 2e 63 6f 6d 2e 63 6e } //2 w.dywt.com.cn
		$a_01_3 = {63 3a 5c 31 32 33 2e 65 78 65 } //2 c:\123.exe
		$a_01_4 = {68 61 6f 68 61 63 6b 2e 63 6f 6d 2f } //2 haohack.com/
		$a_01_5 = {54 72 61 6e 73 66 65 72 2d 45 6e 63 6f 64 69 6e 67 3a 20 62 61 73 65 36 34 } //1 Transfer-Encoding: base64
		$a_01_6 = {74 79 70 65 3a 20 6d 75 6c 74 69 70 61 72 74 2f 6d 69 78 65 64 3b } //1 type: multipart/mixed;
		$a_01_7 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b } //1 Mozilla/4.0 (compatible;
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=12
 
}