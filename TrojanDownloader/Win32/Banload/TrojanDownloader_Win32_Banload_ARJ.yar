
rule TrojanDownloader_Win32_Banload_ARJ{
	meta:
		description = "TrojanDownloader:Win32/Banload.ARJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {54 61 62 4f 72 64 65 72 90 01 03 54 65 78 74 90 01 02 68 74 74 70 90 02 01 3a 2f 2f 90 00 } //01 00 
		$a_03_1 = {ff 84 c0 74 05 e8 90 01 03 ff 68 90 01 02 00 00 e8 90 01 03 ff 8d 55 e8 8b 90 00 } //01 00 
		$a_01_2 = {eb 05 bf 01 00 00 00 8b 45 e8 33 db 8a 5c 38 ff 33 5d e4 3b 5d f0 7f 0b 81 c3 ff 00 00 00 2b 5d f0 eb 03 } //01 00 
		$a_03_3 = {83 c0 50 e8 90 01 03 ff 6a 00 8d 55 90 00 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}