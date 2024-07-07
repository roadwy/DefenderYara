
rule TrojanDownloader_BAT_Scarsi_NZT_MTB{
	meta:
		description = "TrojanDownloader:BAT/Scarsi.NZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 8e 69 5d 91 02 7b 90 01 01 00 00 04 07 91 61 d2 6f 90 01 01 00 00 0a 07 17 58 0b 07 02 7b 90 01 01 00 00 04 8e 69 32 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}