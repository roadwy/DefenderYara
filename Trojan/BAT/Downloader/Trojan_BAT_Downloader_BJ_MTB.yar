
rule Trojan_BAT_Downloader_BJ_MTB{
	meta:
		description = "Trojan:BAT/Downloader.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 } //01 00  https://cdn.discordapp.com/attachments
		$a_81_1 = {62 69 6e 2e 65 78 65 } //01 00  bin.exe
		$a_01_2 = {43 6f 6e 76 65 72 74 } //01 00  Convert
		$a_01_3 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_5 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggableAttribute
	condition:
		any of ($a_*)
 
}