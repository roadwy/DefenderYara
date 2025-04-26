
rule TrojanDownloader_BAT_Lazy_RDF_MTB{
	meta:
		description = "TrojanDownloader:BAT/Lazy.RDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 08 00 00 0a 6f 09 00 00 0a 6f 0a 00 00 0a 73 0b 00 00 0a 20 a2 10 40 05 6f 0c 00 00 0a 13 01 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}