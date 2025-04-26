
rule TrojanDownloader_BAT_Tiny_PB_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {28 06 00 00 0a 72 01 00 00 70 28 07 00 00 0a 18 73 08 00 00 0a 0a 00 72 ?? 00 00 70 28 09 00 00 0a 28 02 00 00 06 0b 06 07 16 07 8e 69 6f ?? 00 00 0a 00 00 de } //1
		$a_00_1 = {28 06 00 00 0a 72 01 00 00 70 28 07 00 00 0a 28 0c 00 00 0a 26 00 de } //1
		$a_00_2 = {00 20 00 0c 00 00 28 0e 00 00 0a 00 06 02 6f 0f 00 00 0a 0b de } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}