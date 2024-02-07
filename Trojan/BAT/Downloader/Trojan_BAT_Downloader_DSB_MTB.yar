
rule Trojan_BAT_Downloader_DSB_MTB{
	meta:
		description = "Trojan:BAT/Downloader.DSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 74 72 61 6e 73 66 65 72 2e 73 68 2f 67 65 74 2f 31 4f 34 71 4e 62 5a 2f 61 73 73 2e 64 6c 6c } //01 00  https://transfer.sh/get/1O4qNbZ/ass.dll
		$a_01_1 = {24 35 63 31 65 32 34 37 62 2d 39 66 34 31 2d 34 64 34 66 2d 39 35 35 34 2d 34 35 36 37 63 61 62 39 36 65 31 31 } //01 00  $5c1e247b-9f41-4d4f-9554-4567cab96e11
		$a_01_2 = {4b 69 63 6b 41 73 73 2e 65 78 65 } //01 00  KickAss.exe
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //00 00  DownloadData
	condition:
		any of ($a_*)
 
}