
rule TrojanDownloader_BAT_Pwsx_SM_MTB{
	meta:
		description = "TrojanDownloader:BAT/Pwsx.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 08 6f 8f 00 00 0a 5d 13 06 09 08 6f 8f 00 00 0a 5b 13 07 08 72 06 05 00 70 18 18 8d 1d 00 00 01 25 16 11 06 8c 3f 00 00 01 a2 25 17 11 07 8c 3f 00 00 01 a2 28 90 00 00 0a a5 2d 00 00 01 13 08 12 08 28 91 00 00 0a 13 09 07 11 09 6f 92 00 00 0a 09 17 58 0d 09 08 6f 8f 00 00 0a 08 6f 93 00 00 0a 5a 32 9a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}