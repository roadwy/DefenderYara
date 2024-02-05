
rule TrojanDownloader_BAT_Seraph_SU_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.SU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 2b 06 16 2c 0a 26 de 0d 28 90 01 03 06 2b f3 0c 2b f4 26 de 00 08 2c e7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_BAT_Seraph_SU_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Seraph.SU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 05 72 8d 00 00 70 6f 0d 00 00 0a 6f 0e 00 00 0a 6f 0f 00 00 0a 6f 10 00 00 0a 6f 11 00 00 0a 13 04 dd 0f 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}