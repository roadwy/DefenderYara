
rule TrojanDownloader_BAT_Malgent_RP_MTB{
	meta:
		description = "TrojanDownloader:BAT/Malgent.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 2d 1c 15 2c 19 08 07 09 18 6f 12 00 00 0a 1f 10 28 13 00 00 0a 6f 14 00 00 0a 09 18 58 0d 09 07 6f 15 00 00 0a 16 2d 1d 32 d5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}