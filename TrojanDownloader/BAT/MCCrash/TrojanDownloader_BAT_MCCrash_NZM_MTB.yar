
rule TrojanDownloader_BAT_MCCrash_NZM_MTB{
	meta:
		description = "TrojanDownloader:BAT/MCCrash.NZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 25 72 31 00 00 70 6f 90 01 01 00 00 0a 25 72 41 00 00 70 6f 0b 00 00 0a 6f 0c 00 00 0a 25 6f 0d 00 00 0a 26 90 00 } //1
		$a_81_1 = {57 69 6e 64 6f 77 73 2f 73 76 63 68 6f 73 74 2e 65 78 65 } //1 Windows/svchost.exe
		$a_81_2 = {72 65 70 6f 2e 61 72 6b 2d 65 76 65 6e 74 2e 6e 65 74 2f 64 6f 77 6e 6c 6f 61 64 73 2f 73 76 63 68 6f 73 74 73 2e 65 78 65 } //1 repo.ark-event.net/downloads/svchosts.exe
		$a_81_3 = {4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 Net.WebClient).DownloadFile
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}