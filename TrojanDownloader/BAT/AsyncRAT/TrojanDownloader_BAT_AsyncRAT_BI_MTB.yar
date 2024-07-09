
rule TrojanDownloader_BAT_AsyncRAT_BI_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 06 08 06 8e 69 5d 91 7e ?? 00 00 04 08 91 61 d2 6f ?? 00 00 0a 08 17 58 0c } //2
		$a_01_1 = {00 00 0a 20 00 01 00 00 14 14 14 6f } //2
		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 } //1 GetResponse
		$a_01_3 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}