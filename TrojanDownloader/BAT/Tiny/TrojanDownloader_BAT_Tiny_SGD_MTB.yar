
rule TrojanDownloader_BAT_Tiny_SGD_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.SGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 04 28 01 00 00 06 02 28 02 00 00 06 00 00 2b 02 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}