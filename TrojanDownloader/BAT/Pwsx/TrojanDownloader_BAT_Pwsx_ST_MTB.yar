
rule TrojanDownloader_BAT_Pwsx_ST_MTB{
	meta:
		description = "TrojanDownloader:BAT/Pwsx.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 06 17 58 09 5d 91 13 0c 07 06 91 13 0d 08 06 08 6f 72 00 00 0a 5d 6f 73 00 00 0a 13 0e 11 0d 11 0e 61 11 0c 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0f 07 06 11 0f d2 9c 06 17 58 0a 06 09 fe 04 13 10 11 10 2d b8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}