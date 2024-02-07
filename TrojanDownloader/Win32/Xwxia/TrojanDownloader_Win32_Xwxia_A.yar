
rule TrojanDownloader_Win32_Xwxia_A{
	meta:
		description = "TrojanDownloader:Win32/Xwxia.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 6e 70 64 72 6d 76 2e 6a 70 67 22 20 2f 71 20 2f 66 } //01 00  \npdrmv.jpg" /q /f
		$a_01_1 = {25 4d 59 46 49 4c 45 53 25 5c 63 6f 6f 70 65 6e 5f 73 65 74 75 70 } //01 00  %MYFILES%\coopen_setup
		$a_01_2 = {2e 7a 75 69 68 6f 75 79 69 2e 63 6f 6d 2f } //01 00  .zuihouyi.com/
		$a_01_3 = {61 2e 78 77 78 69 61 7a 61 69 2e 63 6f 6d 2f } //01 00  a.xwxiazai.com/
		$a_01_4 = {2e 30 37 33 39 36 2e 63 6f 6d 2f } //00 00  .07396.com/
	condition:
		any of ($a_*)
 
}