
rule TrojanDownloader_BAT_Heracles_VU_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.VU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 06 06 9e 06 17 58 0a 06 20 ff 00 00 00 fe 03 16 fe 01 13 0d 11 0d 2d e7 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule TrojanDownloader_BAT_Heracles_VU_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Heracles.VU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {91 2b 3a 08 07 6f 19 00 00 0a 5d 6f 1a 00 00 0a 61 d2 9c 16 2d df 1a 2c dc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}