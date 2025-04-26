
rule TrojanDownloader_BAT_Ader_ARAA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Ader.ARAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 03 11 06 91 07 11 06 07 8e 69 5d 91 61 08 61 d2 6f ?? ?? ?? 0a 00 00 11 06 17 58 13 06 11 06 03 8e 69 fe 04 13 07 11 07 2d d4 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}