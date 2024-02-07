
rule TrojanDownloader_Win32_CryptInject_BG_MTB{
	meta:
		description = "TrojanDownloader:Win32/CryptInject.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 61 73 74 6d 65 64 69 61 33 33 34 37 2e 63 6f 2e 63 63 2f 64 2f 64 6e 6c 2e 70 68 70 } //01 00  eastmedia3347.co.cc/d/dnl.php
		$a_01_1 = {68 74 74 70 62 2e 65 78 65 } //01 00  httpb.exe
		$a_01_2 = {68 74 74 70 62 20 72 75 6e 20 6b 65 79 } //01 00  httpb run key
		$a_01_3 = {73 72 65 6d 6f 76 65 4d 65 25 69 25 69 25 69 25 69 2e 62 61 74 } //00 00  sremoveMe%i%i%i%i.bat
	condition:
		any of ($a_*)
 
}