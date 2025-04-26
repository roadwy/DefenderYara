
rule TrojanDownloader_BAT_FormBook_NYH_MTB{
	meta:
		description = "TrojanDownloader:BAT/FormBook.NYH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 09 07 8e 69 5d 91 06 09 91 61 d2 6f ?? 00 00 0a 09 17 58 0d 09 06 8e 69 32 e3 } //1
		$a_01_1 = {50 4f 5f 32 30 32 32 30 32 38 30 38 39 36 35 38 32 } //1 PO_20220280896582
		$a_01_2 = {15 b6 09 09 0b 00 00 00 10 00 01 00 02 00 00 01 00 00 00 30 00 00 00 08 00 00 00 08 00 00 00 19 00 00 00 0f 00 00 00 38 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}