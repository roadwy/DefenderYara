
rule TrojanDownloader_BAT_Banload_AE{
	meta:
		description = "TrojanDownloader:BAT/Banload.AE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 55 00 50 00 44 00 54 00 48 00 50 00 50 00 5c 00 6b 00 65 00 79 00 2e 00 63 00 65 00 6c 00 } //01 00 
		$a_00_1 = {54 00 6f 00 74 00 61 00 6c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 65 00 72 00 2e 00 } //01 00 
		$a_01_2 = {4b 65 79 5f 43 65 6c } //00 00 
	condition:
		any of ($a_*)
 
}