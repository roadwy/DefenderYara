
rule TrojanDownloader_BAT_Seraph_ARAX_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f ?? ?? ?? 0a 11 04 16 2d e0 17 25 2c 07 58 13 04 11 04 07 8e 69 1b 2c f2 32 d6 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}