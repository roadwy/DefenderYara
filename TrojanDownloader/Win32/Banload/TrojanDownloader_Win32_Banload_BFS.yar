
rule TrojanDownloader_Win32_Banload_BFS{
	meta:
		description = "TrojanDownloader:Win32/Banload.BFS,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {32 30 30 2e 39 38 2e 31 33 30 2e 38 30 2f 72 63 6f } //01 00 
		$a_01_1 = {5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 69 64 } //00 00 
		$a_00_2 = {5d 04 00 00 74 6b 03 80 5c 25 } //00 00 
	condition:
		any of ($a_*)
 
}