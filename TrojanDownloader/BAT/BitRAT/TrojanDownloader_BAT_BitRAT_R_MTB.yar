
rule TrojanDownloader_BAT_BitRAT_R_MTB{
	meta:
		description = "TrojanDownloader:BAT/BitRAT.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 61 d2 6f 90 09 2d 00 11 90 01 01 28 90 01 01 00 00 0a 72 90 01 01 00 00 70 28 90 01 01 00 00 06 11 90 01 01 28 90 01 01 00 00 0a 72 90 01 01 00 00 70 28 90 01 01 00 00 06 8e 69 5d 91 7e 90 01 01 00 00 04 11 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}