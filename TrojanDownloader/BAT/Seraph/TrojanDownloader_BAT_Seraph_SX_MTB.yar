
rule TrojanDownloader_BAT_Seraph_SX_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 7b 04 00 00 04 03 04 58 06 58 6f 13 00 00 06 06 17 58 0a 06 1b 32 e8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}