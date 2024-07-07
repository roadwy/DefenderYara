
rule TrojanDownloader_BAT_Winpact_A_bit{
	meta:
		description = "TrojanDownloader:BAT/Winpact.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 53 1c 00 70 90 01 01 04 28 5e 00 00 0a 0a 17 03 28 5f 00 00 0a b5 13 04 0d 2b 25 90 01 01 06 03 09 17 28 60 00 00 0a 28 5e 00 00 0a 61 28 61 00 00 0a 28 62 00 00 0a 28 63 00 00 0a 90 01 01 09 17 58 b5 0d 09 11 04 31 d6 90 01 01 2a 90 00 } //2
		$a_01_1 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 } //1 DownloadFile
		$a_01_2 = {45 00 6e 00 76 00 69 00 72 00 6f 00 6e 00 } //1 Environ
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}