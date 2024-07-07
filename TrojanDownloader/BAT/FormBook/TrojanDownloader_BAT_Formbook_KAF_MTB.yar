
rule TrojanDownloader_BAT_Formbook_KAF_MTB{
	meta:
		description = "TrojanDownloader:BAT/Formbook.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 08 11 04 91 72 90 01 01 00 00 70 28 90 01 01 00 00 0a 59 d2 9c 11 04 17 58 13 04 11 04 08 8e 69 32 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}