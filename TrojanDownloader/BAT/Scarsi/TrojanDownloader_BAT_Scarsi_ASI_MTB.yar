
rule TrojanDownloader_BAT_Scarsi_ASI_MTB{
	meta:
		description = "TrojanDownloader:BAT/Scarsi.ASI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 09 11 00 11 05 11 00 91 11 0a 61 d2 9c 20 01 00 00 00 7e 46 00 00 04 7b 4a 00 00 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}