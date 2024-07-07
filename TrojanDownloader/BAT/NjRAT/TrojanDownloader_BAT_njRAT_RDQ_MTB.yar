
rule TrojanDownloader_BAT_njRAT_RDQ_MTB{
	meta:
		description = "TrojanDownloader:BAT/njRAT.RDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0d 07 09 06 08 18 5b 06 6f 16 00 00 0a 5d 6f 17 00 00 0a 61 d1 8c 16 00 00 01 28 18 00 00 0a 0b 08 18 58 0c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}