
rule TrojanDownloader_BAT_Barys_SK_MTB{
	meta:
		description = "TrojanDownloader:BAT/Barys.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 04 00 00 0a 0b 28 90 01 03 0a 03 6f 90 01 03 0a 0c 07 08 16 08 8e 69 6f 90 01 03 0a 0d 73 08 00 00 0a 13 04 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}