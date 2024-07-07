
rule TrojanDownloader_BAT_Seraph_RH_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {14 0a 38 26 00 00 00 00 28 14 00 00 0a 28 23 00 00 06 6f 15 00 00 0a 28 16 00 00 0a 28 08 00 00 06 0a dd 06 00 00 00 26 dd 00 00 00 00 06 2c d7 06 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}