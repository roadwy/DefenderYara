
rule TrojanDownloader_Win32_Regrejaz_A{
	meta:
		description = "TrojanDownloader:Win32/Regrejaz.A,SIGNATURE_TYPE_PEHSTR_EXT,11 00 0f 00 0d 00 00 04 00 "
		
	strings :
		$a_01_0 = {53 79 73 74 65 6d 43 61 63 68 65 2e 62 61 74 } //04 00  SystemCache.bat
		$a_01_1 = {73 79 73 74 65 6d 2e 63 6f 6e 66 } //02 00  system.conf
		$a_01_2 = {23 6b 65 77 6c } //02 00  #kewl
		$a_01_3 = {67 61 74 65 77 61 79 2e 70 68 70 } //02 00  gateway.php
		$a_01_4 = {6d 61 6e 72 65 73 61 2d 70 6c 75 6a 61 2e 63 6f 6d 2f 62 69 6e } //02 00  manresa-pluja.com/bin
		$a_01_5 = {61 72 65 79 6f 75 61 72 65 64 6f 2e 63 6f 6d 2f } //02 00  areyouaredo.com/
		$a_01_6 = {72 65 67 64 72 76 2e 65 78 65 } //02 00  regdrv.exe
		$a_01_7 = {8d 45 e0 0f b7 55 f0 c1 e2 04 0f bf 4d f2 c1 e9 02 0a d1 e8 } //01 00 
		$a_01_8 = {67 6f 6f 67 6c 65 2e 63 6f 6d 2f } //01 00  google.com/
		$a_01_9 = {79 61 68 6f 6f 2e 63 6f 6d 2f } //01 00  yahoo.com/
		$a_01_10 = {61 73 6b 2e 63 6f 6d 2f } //01 00  ask.com/
		$a_01_11 = {61 6c 65 78 61 2e 63 6f 6d 2f } //01 00  alexa.com/
		$a_01_12 = {6c 69 76 65 2e 63 6f 6d 2f } //00 00  live.com/
	condition:
		any of ($a_*)
 
}