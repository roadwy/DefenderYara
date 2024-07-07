
rule TrojanDownloader_BAT_AveMariaRAT_K_MTB{
	meta:
		description = "TrojanDownloader:BAT/AveMariaRAT.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 8e 69 17 59 0c 2b 90 01 01 0b 2b 90 01 01 06 07 91 0d 06 07 06 08 91 9c 06 08 09 9c 07 17 58 0b 08 17 59 0c 07 08 32 90 00 } //2
		$a_01_1 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //1 ReadAsByteArrayAsync
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}