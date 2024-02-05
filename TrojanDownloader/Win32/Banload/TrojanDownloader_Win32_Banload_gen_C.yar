
rule TrojanDownloader_Win32_Banload_gen_C{
	meta:
		description = "TrojanDownloader:Win32/Banload.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 44 10 ff 03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 f0 7d 03 46 eb 05 be 01 00 00 00 8b 45 e8 0f b6 44 30 ff 33 d8 8d 45 cc 50 89 5d d0 c6 45 d4 00 8d 55 d0 33 c9 } //01 00 
		$a_03_1 = {bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 83 ea 1e e8 90 01 03 ff 8b 55 f4 8d 45 f8 e8 90 01 03 ff 43 4e 75 dc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}