
rule TrojanDownloader_Win32_DownAlbu_A{
	meta:
		description = "TrojanDownloader:Win32/DownAlbu.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 6b 69 6e 48 2e 64 6c 6c } //01 00  SkinH.dll
		$a_00_1 = {61 75 74 6f 73 68 75 74 70 63 } //01 00  autoshutpc
		$a_01_2 = {6b 61 69 78 69 6e 30 30 31 41 6c 62 75 6d } //02 00  kaixin001Album
		$a_01_3 = {43 52 45 41 54 45 20 54 41 42 4c 45 20 64 6f 77 6e 68 69 73 } //02 00  CREATE TABLE downhis
		$a_01_4 = {6c 69 6e 79 73 74 61 72 2e 63 6f 6d 2f 6c 6f 67 67 69 6e 67 } //02 00  linystar.com/logging
		$a_01_5 = {64 6f 77 6e 61 6c 62 75 6d 2e 67 6f 6f 67 6c 65 63 6f 64 65 2e 63 6f 6d } //00 00  downalbum.googlecode.com
	condition:
		any of ($a_*)
 
}