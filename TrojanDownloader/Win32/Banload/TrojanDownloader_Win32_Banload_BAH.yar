
rule TrojanDownloader_Win32_Banload_BAH{
	meta:
		description = "TrojanDownloader:Win32/Banload.BAH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {7d 03 47 eb 05 bf 01 00 00 00 8b 45 e4 33 db 8a 5c 38 ff 33 5d e0 3b 5d ec 7f 0b 81 c3 ff 00 00 00 2b 5d ec eb 03 } //01 00 
		$a_03_1 = {c7 45 fc 03 00 00 00 8d 45 e8 89 45 f8 8d 45 dc 89 45 f4 33 c0 55 68 90 01 04 64 ff 30 64 89 20 8d 4d d0 8b 45 f8 8b 10 b8 90 01 04 e8 90 01 04 8b 4d d0 b8 90 01 04 8b 15 90 01 04 e8 90 01 04 8d 4d cc 8b 45 f4 8b 10 b8 90 01 04 e8 90 01 04 8b 45 cc 8b 15 90 01 04 e8 90 01 04 90 90 90 90 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}