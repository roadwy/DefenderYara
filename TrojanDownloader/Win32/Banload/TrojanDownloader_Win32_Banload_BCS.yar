
rule TrojanDownloader_Win32_Banload_BCS{
	meta:
		description = "TrojanDownloader:Win32/Banload.BCS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 6f 69 70 2e 73 31 32 2e 63 6f 6d 2e 62 72 } //01 00  geoip.s12.com.br
		$a_03_1 = {6a 00 6a 00 8b 45 fc e8 90 01 04 50 8d 4d 90 01 01 ba 90 01 04 a1 90 01 04 e8 90 01 04 8b 45 90 01 01 e8 90 01 04 50 6a 00 6a 00 e8 90 00 } //01 00 
		$a_03_2 = {0f b6 44 30 ff 33 c3 89 45 90 01 01 3b 7d 90 01 01 7c 0f 8b 45 90 01 01 05 ff 00 00 00 2b c7 89 45 90 01 01 eb 03 29 7d 90 01 01 8d 45 90 01 01 8b 55 90 01 01 e8 90 01 04 8b 55 90 00 } //01 00 
		$a_03_3 = {85 c0 0f 8f 1b 02 00 00 8d 4d 90 01 01 ba 90 01 04 a1 90 01 04 e8 90 01 04 8b 45 90 01 01 50 8d 55 90 01 01 8b 45 fc e8 90 01 04 8b 55 90 01 01 58 e8 90 01 04 85 c0 0f 8f e9 01 00 00 8d 4d 90 01 01 ba 90 00 } //00 00 
		$a_00_4 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}