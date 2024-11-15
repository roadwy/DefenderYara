
rule TrojanDownloader_BAT_Pwsx_SX_MTB{
	meta:
		description = "TrojanDownloader:BAT/Pwsx.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 07 06 08 8f 68 00 00 01 28 7d 00 00 0a 28 7e 00 00 0a 0b 00 08 17 59 0c 08 15 fe 02 0d 09 2d df } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}