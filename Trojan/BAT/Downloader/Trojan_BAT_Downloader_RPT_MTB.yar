
rule Trojan_BAT_Downloader_RPT_MTB{
	meta:
		description = "Trojan:BAT/Downloader.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 90 02 80 2e 00 64 00 6c 00 6c 00 90 00 } //01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_2 = {54 68 72 65 61 64 } //01 00  Thread
		$a_01_3 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_01_4 = {57 72 69 74 65 4c 69 6e 65 } //01 00  WriteLine
		$a_01_5 = {57 65 62 43 6c 69 65 6e 74 } //01 00  WebClient
		$a_01_6 = {53 6c 65 65 70 } //00 00  Sleep
	condition:
		any of ($a_*)
 
}