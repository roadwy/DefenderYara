
rule TrojanDownloader_BAT_Small_ARAC_MTB{
	meta:
		description = "TrojanDownloader:BAT/Small.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 09 06 09 91 03 11 04 91 08 1d 5f 62 d2 11 04 61 09 d6 20 ff 00 00 00 5f 61 b4 9c 11 04 17 d6 13 04 11 04 11 06 31 d8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}