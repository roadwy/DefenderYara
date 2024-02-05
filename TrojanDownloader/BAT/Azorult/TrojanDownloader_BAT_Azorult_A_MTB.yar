
rule TrojanDownloader_BAT_Azorult_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/Azorult.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ea 58 66 61 fe 90 01 02 00 61 d1 9d fe 90 01 02 00 20 90 01 03 db 65 20 90 01 03 24 59 59 25 fe 90 01 02 00 20 90 01 03 20 20 90 01 03 17 59 65 20 90 01 03 08 61 66 20 90 00 } //01 00 
		$a_01_1 = {08 11 08 08 11 08 91 11 04 11 08 09 5d 91 61 d2 9c 1f 09 13 0f 38 } //00 00 
	condition:
		any of ($a_*)
 
}