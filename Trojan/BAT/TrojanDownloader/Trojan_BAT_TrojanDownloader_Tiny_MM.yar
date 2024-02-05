
rule Trojan_BAT_TrojanDownloader_Tiny_MM{
	meta:
		description = "Trojan:BAT/TrojanDownloader.Tiny.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {70 20 00 00 01 00 72 90 01 03 70 28 90 01 03 0a 26 7e 90 01 03 04 7e 90 01 03 04 7e 90 01 03 04 6f 90 01 03 0a 2b 07 1f 64 28 90 01 03 0a 7e 90 01 03 04 6f 90 01 03 0a 2d ed 7e 90 01 03 04 16 16 15 28 90 01 03 0a 26 2a 90 00 } //05 00 
		$a_80_1 = {44 3a 5c 50 72 6f 67 72 61 6d 6d 69 65 72 75 6e 67 5c 42 69 6e 67 64 77 6e } //D:\Programmierung\Bingdwn  03 00 
		$a_80_2 = {61 73 64 66 2e 65 78 65 } //asdf.exe  03 00 
		$a_80_3 = {67 65 74 5f 49 73 42 75 73 79 } //get_IsBusy  03 00 
		$a_80_4 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //DownloadFile  00 00 
	condition:
		any of ($a_*)
 
}