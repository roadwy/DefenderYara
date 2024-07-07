
rule TrojanDownloader_BAT_Heracles_VQ_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.VQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 5d 0d 07 09 91 11 05 06 1f 16 5d 91 61 13 09 11 09 07 06 17 58 08 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d 13 0a 07 09 11 0a d2 9c 06 17 58 0a 06 08 11 06 17 58 5a fe 04 13 0b 11 0b 2d be } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}