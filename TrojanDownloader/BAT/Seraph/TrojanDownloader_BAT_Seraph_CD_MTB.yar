
rule TrojanDownloader_BAT_Seraph_CD_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 27 00 00 0a 06 6f 28 00 00 0a 28 0c 00 00 06 7e 29 00 00 0a 6f 2a 00 00 0a 28 2b 00 00 0a 2a } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}