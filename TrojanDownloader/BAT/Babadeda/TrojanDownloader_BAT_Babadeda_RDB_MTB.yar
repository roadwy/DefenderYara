
rule TrojanDownloader_BAT_Babadeda_RDB_MTB{
	meta:
		description = "TrojanDownloader:BAT/Babadeda.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {35 32 35 64 35 66 33 31 2d 36 38 38 37 2d 34 30 36 38 2d 39 34 35 39 2d 65 66 33 34 33 64 39 63 34 37 39 33 } //02 00  525d5f31-6887-4068-9459-ef343d9c4793
		$a_01_1 = {08 59 61 d2 13 04 09 1e 63 08 61 d2 13 05 07 08 11 05 1e 62 11 04 60 d1 9d } //00 00 
	condition:
		any of ($a_*)
 
}