
rule TrojanDownloader_BAT_Seraph_ASE_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.ASE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 16 6f ?? 00 00 0a 13 06 12 06 28 ?? 00 00 0a 13 07 11 04 11 07 6f ?? 00 00 0a 11 05 17 58 13 05 11 05 09 6f ?? 00 00 0a 32 d3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}