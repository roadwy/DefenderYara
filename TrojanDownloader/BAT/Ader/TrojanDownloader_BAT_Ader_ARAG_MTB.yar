
rule TrojanDownloader_BAT_Ader_ARAG_MTB{
	meta:
		description = "TrojanDownloader:BAT/Ader.ARAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 06 11 04 06 8e 69 5d 91 08 11 04 91 61 d2 6f ?? ?? ?? 0a 11 04 17 58 13 04 11 04 08 8e 69 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}