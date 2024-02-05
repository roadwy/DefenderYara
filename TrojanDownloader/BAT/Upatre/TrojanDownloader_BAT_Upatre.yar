
rule TrojanDownloader_BAT_Upatre{
	meta:
		description = "TrojanDownloader:BAT/Upatre,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6f 1f 00 00 0a 90 01 01 6f 20 00 00 0a d8 19 d8 17 da 17 d6 8d 18 00 00 01 90 00 } //01 00 
		$a_03_1 = {b7 17 da 11 04 da 02 11 04 91 90 01 01 61 90 01 01 11 04 90 01 01 8e b7 5d 91 61 9c 11 04 17 d6 13 04 11 04 11 05 31 db 90 01 01 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}