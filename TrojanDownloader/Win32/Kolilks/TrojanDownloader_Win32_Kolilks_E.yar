
rule TrojanDownloader_Win32_Kolilks_E{
	meta:
		description = "TrojanDownloader:Win32/Kolilks.E,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 04 00 "
		
	strings :
		$a_01_0 = {2f 6b 69 6c 6c 73 2e 74 78 74 3f 74 } //02 00  /kills.txt?t
		$a_01_1 = {83 c9 ff 8b f7 8d 54 24 0c 8b fa f2 ae 8b cb c1 e9 02 4f f3 a5 8b cb 83 e1 03 f3 a4 } //02 00 
		$a_01_2 = {b9 1a 00 00 00 f7 f9 80 c2 41 88 54 34 0c 46 3b f7 7c ea } //01 00 
		$a_01_3 = {2e 6c 6d 6f 6b 31 32 33 2e 63 6f 6d 2f } //01 00  .lmok123.com/
		$a_01_4 = {62 61 69 64 75 61 73 70 2e 77 65 62 31 39 34 2e 64 6e 73 39 31 31 2e 63 6e 2f } //01 00  baiduasp.web194.dns911.cn/
		$a_01_5 = {2f 31 32 32 2e 32 32 34 2e 39 2e 31 35 31 2f } //00 00  /122.224.9.151/
		$a_00_6 = {5d 04 00 00 b9 } //30 03 
	condition:
		any of ($a_*)
 
}