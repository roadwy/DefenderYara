
rule TrojanDownloader_BAT_Androm_CXD_MTB{
	meta:
		description = "TrojanDownloader:BAT/Androm.CXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {6f 1a 00 00 0a 13 04 de 7c 07 2b c1 73 90 01 04 2b c1 73 90 01 04 2b bc 0d 2b 90 00 } //05 00 
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 34 00 35 00 2e 00 39 00 33 00 2e 00 32 00 30 00 31 00 2e 00 36 00 32 00 2f } //00 00 
	condition:
		any of ($a_*)
 
}