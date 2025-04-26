
rule TrojanDownloader_BAT_RedLine_NZT_MTB{
	meta:
		description = "TrojanDownloader:BAT/RedLine.NZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {61 48 52 30 63 48 4d 36 4c 79 39 76 62 6d 55 75 62 47 6c 30 5a 58 4e 6f 59 58 4a 6c 4c 6d 4e 76 4c 32 52 76 64 32 35 73 62 32 46 6b 4c 6e 42 6f 63 44 39 } //1 aHR0cHM6Ly9vbmUubGl0ZXNoYXJlLmNvL2Rvd25sb2FkLnBocD9
		$a_81_1 = {68 65 64 65 66 69 6d 62 65 6c 6c 69 } //1 hedefimbelli
		$a_01_2 = {79 00 65 00 6e 00 69 00 6c 00 6d 00 65 00 6d 00 65 00 7a 00 69 00 6c 00 6d 00 65 00 6d 00 2e 00 72 00 61 00 76 00 65 00 6e 00 6e 00 61 00 62 00 61 00 63 00 6b 00 } //1 yenilmemezilmem.ravennaback
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}