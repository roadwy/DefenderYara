
rule TrojanDownloader_BAT_Formbook_RDM_MTB{
	meta:
		description = "TrojanDownloader:BAT/Formbook.RDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 03 00 00 0a 6f 04 00 00 0a 28 0e 00 00 06 6f 05 00 00 0a 6f 06 00 00 0a 13 03 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}