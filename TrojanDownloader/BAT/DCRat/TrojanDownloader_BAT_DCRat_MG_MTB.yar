
rule TrojanDownloader_BAT_DCRat_MG_MTB{
	meta:
		description = "TrojanDownloader:BAT/DCRat.MG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 25 00 00 06 72 01 00 00 70 6f 08 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}