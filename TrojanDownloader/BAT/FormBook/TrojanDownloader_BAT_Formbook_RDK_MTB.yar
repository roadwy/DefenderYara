
rule TrojanDownloader_BAT_Formbook_RDK_MTB{
	meta:
		description = "TrojanDownloader:BAT/Formbook.RDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 19 00 00 0a 6f 1a 00 00 0a 00 06 6f 1b 00 00 0a 02 16 02 8e 69 6f 1c 00 00 0a 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}