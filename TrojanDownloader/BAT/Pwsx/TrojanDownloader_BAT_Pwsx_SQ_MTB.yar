
rule TrojanDownloader_BAT_Pwsx_SQ_MTB{
	meta:
		description = "TrojanDownloader:BAT/Pwsx.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 20 00 01 00 00 13 06 11 05 17 58 13 07 11 05 20 00 3a 01 00 5d 13 08 11 07 20 00 3a 01 00 5d 13 09 07 11 09 91 11 06 58 13 0a 07 11 08 91 13 0b 08 11 05 1f 16 5d 91 13 0c 11 0b 11 0c 61 13 0d 07 11 08 11 0d 11 0a 59 11 06 5d d2 9c 00 11 05 17 58 13 05 11 05 20 00 3a 01 00 fe 04 13 0e 11 0e 2d 9c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}