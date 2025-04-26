
rule TrojanDownloader_BAT_AsyncRAT_SM_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 05 11 04 5d 13 08 11 05 1f 16 5d 13 09 11 05 17 58 11 04 5d 13 0a 07 11 08 91 08 11 09 91 61 13 0b 11 0b 07 11 0a 91 59 20 00 01 00 00 58 20 00 01 00 00 5d 13 0c 07 11 08 11 0c d2 9c 11 05 17 58 13 05 00 11 05 11 04 09 17 58 5a fe 04 13 0d 11 0d 2d aa } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}