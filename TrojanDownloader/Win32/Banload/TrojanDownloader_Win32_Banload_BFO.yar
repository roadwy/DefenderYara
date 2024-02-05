
rule TrojanDownloader_Win32_Banload_BFO{
	meta:
		description = "TrojanDownloader:Win32/Banload.BFO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 7a 6c 69 62 90 02 10 5c 90 02 10 2e 65 78 65 90 02 04 6f 70 65 6e 90 00 } //01 00 
		$a_03_1 = {5f 01 00 e8 90 09 3a 00 6a 00 68 90 01 04 68 90 01 04 8d 45 90 01 01 b9 90 01 04 8b 15 90 01 04 e8 90 01 04 8b 45 90 01 01 e8 90 01 04 50 68 90 01 04 a1 90 01 04 50 e8 90 01 04 68 90 90 90 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}