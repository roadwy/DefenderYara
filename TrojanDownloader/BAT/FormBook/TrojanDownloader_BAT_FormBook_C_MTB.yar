
rule TrojanDownloader_BAT_FormBook_C_MTB{
	meta:
		description = "TrojanDownloader:BAT/FormBook.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {1b 11 06 16 16 02 17 8d ?? 00 00 01 25 16 11 06 8c ?? 00 00 01 a2 14 28 } //2
		$a_03_1 = {01 20 10 27 00 00 6f ?? 00 00 0a 07 75 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}