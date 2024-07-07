
rule TrojanDownloader_BAT_PsDownload_ABAS_MTB{
	meta:
		description = "TrojanDownloader:BAT/PsDownload.ABAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 0b 16 0a 2b 36 07 13 05 16 13 06 11 05 12 06 28 90 01 01 00 00 0a 07 09 06 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a de 0c 11 06 2c 07 11 05 28 90 01 01 00 00 0a dc 06 18 58 0a 06 09 6f 90 01 01 00 00 0a fe 04 13 07 11 07 2d bb 07 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 13 08 11 08 90 00 } //10
		$a_01_1 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //1 ReadAsByteArrayAsync
		$a_01_2 = {48 74 74 70 52 65 73 70 6f 6e 73 65 4d 65 73 73 61 67 65 } //1 HttpResponseMessage
		$a_01_3 = {48 74 74 70 43 6c 69 65 6e 74 } //1 HttpClient
		$a_01_4 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_5 = {47 65 74 41 73 79 6e 63 } //1 GetAsync
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}