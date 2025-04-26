
rule TrojanDownloader_BAT_Ader_ARAF_MTB{
	meta:
		description = "TrojanDownloader:BAT/Ader.ARAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f ?? ?? ?? 0a 11 04 13 05 11 05 17 58 13 04 11 04 07 8e 69 32 db } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}