
rule TrojanDownloader_BAT_PureCrypter_I_MTB{
	meta:
		description = "TrojanDownloader:BAT/PureCrypter.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 02 16 11 02 8e 69 } //02 00 
		$a_01_1 = {11 02 8e 69 20 40 42 0f } //02 00 
		$a_03_2 = {20 80 3e 00 00 8d 90 01 01 00 00 01 13 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}