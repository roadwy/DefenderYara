
rule TrojanDownloader_BAT_zgRAT_H_MTB{
	meta:
		description = "TrojanDownloader:BAT/zgRAT.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {70 20 00 01 00 00 14 14 14 6f ?? 00 00 0a 26 20 } //2
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_2 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //1 GetExportedTypes
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}