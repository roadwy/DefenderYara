
rule TrojanDownloader_BAT_Gendwnurl_BJ_bit{
	meta:
		description = "TrojanDownloader:BAT/Gendwnurl.BJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 34 00 37 00 2e 00 38 00 39 00 2e 00 31 00 38 00 37 00 2e 00 35 00 34 00 90 02 20 2e 00 72 00 61 00 72 00 20 00 43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 90 02 10 2e 00 65 00 78 00 65 00 90 00 } //1
		$a_01_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {2f 00 6b 00 20 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 } //1 /k DownloadFile
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}