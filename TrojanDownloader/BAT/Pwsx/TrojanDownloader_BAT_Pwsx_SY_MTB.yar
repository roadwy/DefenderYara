
rule TrojanDownloader_BAT_Pwsx_SY_MTB{
	meta:
		description = "TrojanDownloader:BAT/Pwsx.SY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8e 69 5d 91 61 d2 9c 00 06 17 58 0a 06 7e 04 00 00 04 8e 69 fe 04 0b 07 2d cf } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}