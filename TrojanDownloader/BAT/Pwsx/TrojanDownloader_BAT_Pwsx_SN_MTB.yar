
rule TrojanDownloader_BAT_Pwsx_SN_MTB{
	meta:
		description = "TrojanDownloader:BAT/Pwsx.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 04 5d 13 06 06 11 07 5d 13 0a 07 11 06 91 13 0b 11 05 11 0a 6f 90 01 03 0a 13 0c 07 06 17 58 11 04 5d 91 13 0d 11 0b 11 0c 61 11 0d 59 20 00 01 00 00 58 13 0e 07 11 06 11 0e 20 00 01 00 00 5d d2 9c 06 17 59 0a 06 16 fe 04 16 fe 01 13 0f 11 0f 2d ab 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}