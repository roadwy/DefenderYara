
rule TrojanDownloader_BAT_Wagex_AWX_MTB{
	meta:
		description = "TrojanDownloader:BAT/Wagex.AWX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 8e 69 0b 2b 0c 00 06 02 07 91 6f 2d 00 00 0a 00 00 07 25 17 59 0b 16 fe 02 0c 08 2d e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}