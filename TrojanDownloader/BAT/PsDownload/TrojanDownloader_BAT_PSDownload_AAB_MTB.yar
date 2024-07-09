
rule TrojanDownloader_BAT_PSDownload_AAB_MTB{
	meta:
		description = "TrojanDownloader:BAT/PSDownload.AAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_03_0 = {06 07 06 08 91 9c 06 08 09 9c 07 17 58 0b 08 17 59 0c 07 16 2d cd 08 32 d7 06 2a 0a 38 ?? ?? ?? ?? 06 2b b5 06 2b bb 0c } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //2 FromBase64String
		$a_01_2 = {48 74 74 70 43 6c 69 65 6e 74 } //2 HttpClient
		$a_01_3 = {47 65 74 53 74 72 69 6e 67 } //2 GetString
		$a_01_4 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //2 ReadAsByteArrayAsync
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}