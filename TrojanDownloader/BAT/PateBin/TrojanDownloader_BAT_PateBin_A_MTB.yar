
rule TrojanDownloader_BAT_PateBin_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/PateBin.A!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 61 00 77 00 2f 00 51 00 47 00 57 00 6a 00 52 00 4d 00 71 00 4c 00 } //1 pastebin.com/raw/QGWjRMqL
		$a_01_1 = {70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 61 00 77 00 2f 00 69 00 70 00 43 00 45 00 43 00 30 00 7a 00 63 00 } //1 pastebin.com/raw/ipCEC0zc
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}