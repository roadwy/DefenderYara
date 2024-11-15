
rule TrojanDownloader_BAT_Small_ABR_MTB{
	meta:
		description = "TrojanDownloader:BAT/Small.ABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 0a 28 02 00 00 06 00 28 04 00 00 0a 72 04 01 00 70 28 05 00 00 0a 0b 07 28 06 00 00 0a 26 72 9f 01 00 70 07 72 4c 02 00 70 28 05 00 00 0a 28 03 00 00 06 00 72 68 02 00 70 07 72 15 03 00 70 28 05 00 00 0a 28 03 00 00 06 00 72 31 03 00 70 07 28 07 00 00 0a 0c 72 d2 03 00 70 08 28 08 00 00 0a 26 20 60 ea 00 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}