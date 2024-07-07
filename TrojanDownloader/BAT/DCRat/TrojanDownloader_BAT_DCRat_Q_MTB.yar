
rule TrojanDownloader_BAT_DCRat_Q_MTB{
	meta:
		description = "TrojanDownloader:BAT/DCRat.Q!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 0a de 03 26 de ca 06 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 28 90 01 01 00 00 2b 6f 90 01 01 00 00 0a 28 90 01 01 00 00 2b 14 14 6f 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}