
rule TrojanDownloader_BAT_DCRat_R_MTB{
	meta:
		description = "TrojanDownloader:BAT/DCRat.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 8e 69 17 5b 8d ?? 00 00 01 0a 16 0b } //2
		$a_03_1 = {06 07 17 5b 7e ?? 00 00 0a a4 ?? 00 00 01 07 17 58 0b 07 02 8e 69 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}