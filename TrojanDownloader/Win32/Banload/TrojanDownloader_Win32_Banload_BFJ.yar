
rule TrojanDownloader_Win32_Banload_BFJ{
	meta:
		description = "TrojanDownloader:Win32/Banload.BFJ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2e 62 72 2f } //01 00 
		$a_01_1 = {41 53 6b 79 6c 69 6e 65 2e 65 78 65 } //01 00 
		$a_01_2 = {5d 51 51 55 8b 96 96 } //01 00 
		$a_03_3 = {ff 83 c0 04 ba 90 01 02 69 00 e8 90 01 03 ff 33 c0 55 68 90 01 02 69 00 64 ff 30 64 89 20 8d 55 e4 b8 90 01 02 69 00 e8 5a fa ff ff 8b 55 e4 90 00 } //00 00 
		$a_00_4 = {80 10 00 } //00 37 
	condition:
		any of ($a_*)
 
}