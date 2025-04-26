
rule TrojanDownloader_BAT_Ader_SS_MTB{
	meta:
		description = "TrojanDownloader:BAT/Ader.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 05 8e 69 42 ?? ?? ?? 00 04 38 ?? ?? ?? 00 05 8e 69 0a 03 05 16 06 6f 1a 00 00 0a 26 02 05 16 06 28 28 00 00 06 04 06 59 10 02 04 16 42 ce ff ff ff } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}