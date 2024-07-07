
rule TrojanDownloader_BAT_AsyncRAT_S_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 13 07 16 13 09 11 07 12 09 28 90 01 01 00 00 0a 08 11 06 06 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a de 90 00 } //2
		$a_03_1 = {06 18 58 0a 06 11 06 6f 90 01 01 00 00 0a fe 04 13 0a 11 0a 2d 90 00 } //2
		$a_01_2 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}