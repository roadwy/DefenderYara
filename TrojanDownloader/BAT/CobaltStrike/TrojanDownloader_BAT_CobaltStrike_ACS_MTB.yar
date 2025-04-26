
rule TrojanDownloader_BAT_CobaltStrike_ACS_MTB{
	meta:
		description = "TrojanDownloader:BAT/CobaltStrike.ACS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 59 0c 17 0d 2b 2d 17 13 04 2b 1f 02 11 04 09 6f 16 00 00 0a 13 05 06 12 05 28 17 00 00 0a 6f 18 00 00 0a 26 11 04 17 58 13 04 11 04 07 31 dc 09 17 58 0d 09 08 31 cf } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}