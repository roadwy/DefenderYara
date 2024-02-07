
rule TrojanDownloader_Win32_Banload_BFZ{
	meta:
		description = "TrojanDownloader:Win32/Banload.BFZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 b9 bf 28 00 00 ba 90 01 04 8b 83 90 01 02 00 00 e8 90 01 04 8b 83 90 01 02 00 00 e8 90 01 04 a1 90 01 04 e8 90 01 04 8b d0 90 00 } //01 00 
		$a_01_1 = {41 64 6d 69 6e 69 73 74 72 61 74 6f 72 00 } //01 00  摁業楮瑳慲潴r
		$a_01_2 = {72 75 6e 61 73 00 } //00 00  畲慮s
	condition:
		any of ($a_*)
 
}