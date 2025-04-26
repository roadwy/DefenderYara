
rule TrojanDownloader_Win32_Regrejaz_A{
	meta:
		description = "TrojanDownloader:Win32/Regrejaz.A,SIGNATURE_TYPE_PEHSTR_EXT,11 00 0f 00 0d 00 00 "
		
	strings :
		$a_01_0 = {53 79 73 74 65 6d 43 61 63 68 65 2e 62 61 74 } //4 SystemCache.bat
		$a_01_1 = {73 79 73 74 65 6d 2e 63 6f 6e 66 } //4 system.conf
		$a_01_2 = {23 6b 65 77 6c } //2 #kewl
		$a_01_3 = {67 61 74 65 77 61 79 2e 70 68 70 } //2 gateway.php
		$a_01_4 = {6d 61 6e 72 65 73 61 2d 70 6c 75 6a 61 2e 63 6f 6d 2f 62 69 6e } //2 manresa-pluja.com/bin
		$a_01_5 = {61 72 65 79 6f 75 61 72 65 64 6f 2e 63 6f 6d 2f } //2 areyouaredo.com/
		$a_01_6 = {72 65 67 64 72 76 2e 65 78 65 } //2 regdrv.exe
		$a_01_7 = {8d 45 e0 0f b7 55 f0 c1 e2 04 0f bf 4d f2 c1 e9 02 0a d1 e8 } //2
		$a_01_8 = {67 6f 6f 67 6c 65 2e 63 6f 6d 2f } //1 google.com/
		$a_01_9 = {79 61 68 6f 6f 2e 63 6f 6d 2f } //1 yahoo.com/
		$a_01_10 = {61 73 6b 2e 63 6f 6d 2f } //1 ask.com/
		$a_01_11 = {61 6c 65 78 61 2e 63 6f 6d 2f } //1 alexa.com/
		$a_01_12 = {6c 69 76 65 2e 63 6f 6d 2f } //1 live.com/
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=15
 
}