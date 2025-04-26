
rule TrojanDownloader_BAT_Adload{
	meta:
		description = "TrojanDownloader:BAT/Adload,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 61 00 73 00 65 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 67 00 61 00 74 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 61 00 66 00 65 00 5f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2f 00 35 00 38 00 32 00 33 00 36 00 39 00 2f 00 41 00 64 00 73 00 53 00 68 00 6f 00 77 00 2e 00 65 00 78 00 65 00 } //1 http://asedownloadgate.com/safe_download/582369/AdsShow.exe
	condition:
		((#a_01_0  & 1)*1) >=1
 
}