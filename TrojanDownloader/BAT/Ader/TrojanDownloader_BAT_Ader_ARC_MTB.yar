
rule TrojanDownloader_BAT_Ader_ARC_MTB{
	meta:
		description = "TrojanDownloader:BAT/Ader.ARC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 09 11 04 09 8e 69 5d 91 08 11 04 91 61 d2 6f 2b 00 00 0a 11 04 17 58 13 04 11 04 08 8e 69 32 df } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}