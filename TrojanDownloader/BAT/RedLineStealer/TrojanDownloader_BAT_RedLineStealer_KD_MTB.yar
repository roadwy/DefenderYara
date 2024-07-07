
rule TrojanDownloader_BAT_RedLineStealer_KD_MTB{
	meta:
		description = "TrojanDownloader:BAT/RedLineStealer.KD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 08 9a 0d 09 6f 90 01 01 00 00 0a 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 13 04 11 04 2c 90 00 } //2
		$a_03_1 = {00 00 0a 13 05 11 05 72 90 01 01 00 00 70 6f 90 01 01 00 00 0a 13 06 11 06 14 14 6f 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}