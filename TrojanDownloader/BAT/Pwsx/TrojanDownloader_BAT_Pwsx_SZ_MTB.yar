
rule TrojanDownloader_BAT_Pwsx_SZ_MTB{
	meta:
		description = "TrojanDownloader:BAT/Pwsx.SZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 1d 5d 16 fe 01 13 05 11 05 2c 0d 06 11 04 06 11 04 91 1f 4f 61 b4 9c 00 00 11 04 17 d6 13 04 11 04 09 31 da } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}