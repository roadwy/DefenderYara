
rule TrojanDownloader_BAT_Tiny_MVE_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.MVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {75 70 6c 6f 61 64 2e 65 65 2f 64 6f 77 6e 6c 6f 61 64 2f } //upload.ee/download/  01 00 
		$a_80_1 = {48 61 6c 6c 61 6a 2e 74 78 74 } //Hallaj.txt  01 00 
		$a_80_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //DownloadString  05 00 
		$a_80_3 = {66 67 68 66 67 66 64 67 2e 65 78 65 } //fghfgfdg.exe  05 00 
		$a_00_4 = {64 61 77 6e 6c 6f 65 64 6b 6c 61 2e 65 78 65 } //00 00  dawnloedkla.exe
	condition:
		any of ($a_*)
 
}