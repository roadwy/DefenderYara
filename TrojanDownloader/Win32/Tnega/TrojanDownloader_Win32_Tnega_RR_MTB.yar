
rule TrojanDownloader_Win32_Tnega_RR_MTB{
	meta:
		description = "TrojanDownloader:Win32/Tnega.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 5c 24 10 48 89 74 24 18 48 89 7c 24 20 55 48 8b ec 48 83 ec 70 48 8b 05 3e 4e 00 00 48 33 c4 48 89 45 f0 48 8b d9 48 8b d1 33 f6 } //1
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 } //1 URLDownloadToFileW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}