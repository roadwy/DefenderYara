
rule TrojanDownloader_Win32_Banload_ZD{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {78 73 65 72 76 69 63 65 78 } //01 00  xservicex
		$a_00_1 = {5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 } //01 00  坜湩潤獷䍜牵敲瑮敖獲潩屮畒n
		$a_03_2 = {6a 00 6a 00 8b 45 f8 e8 90 01 04 50 8b 45 fc e8 90 01 04 50 6a 00 e8 90 01 04 85 c0 0f 94 c3 33 c0 5a 59 59 64 89 10 eb 0c e9 90 01 04 33 db e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}