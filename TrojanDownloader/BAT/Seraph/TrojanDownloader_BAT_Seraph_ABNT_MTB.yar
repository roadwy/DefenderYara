
rule TrojanDownloader_BAT_Seraph_ABNT_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.ABNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 04 06 09 06 09 8e 69 5d 91 08 06 91 61 d2 6f ?? ?? ?? 0a 06 16 2d df 17 58 0a 16 2d b7 06 08 8e 69 32 dc 11 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 2b 13 06 1d 2c b7 } //4
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_2 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}