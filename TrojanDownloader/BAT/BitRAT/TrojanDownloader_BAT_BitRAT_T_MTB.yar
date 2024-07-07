
rule TrojanDownloader_BAT_BitRAT_T_MTB{
	meta:
		description = "TrojanDownloader:BAT/BitRAT.T!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 11 07 72 90 01 02 00 70 28 90 01 01 00 00 0a 16 8d 90 01 01 00 00 01 6f 90 01 01 00 00 0a 26 20 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}