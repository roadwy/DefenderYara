
rule TrojanDownloader_Win32_Banload_ARR{
	meta:
		description = "TrojanDownloader:Win32/Banload.ARR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b7 54 72 fe 66 2b d7 66 f7 d2 e8 90 01 04 8b 55 90 01 01 8d 45 90 01 01 e8 90 01 04 46 4b 75 db 90 00 } //01 00 
		$a_01_1 = {63 6d 64 20 2f 63 20 73 74 61 72 74 20 63 3a 5c 61 72 71 75 69 76 7e 31 5c 77 6c 61 6e 61 70 70 2e 63 70 6c } //00 00 
	condition:
		any of ($a_*)
 
}