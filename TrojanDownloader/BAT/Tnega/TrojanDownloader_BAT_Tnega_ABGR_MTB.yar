
rule TrojanDownloader_BAT_Tnega_ABGR_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tnega.ABGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 0c 16 0d 08 12 03 28 90 01 03 0a 06 02 07 28 90 01 03 06 6f 90 01 03 0a de 0a 09 2c 06 08 28 90 01 03 0a dc 90 00 } //01 00 
		$a_03_1 = {02 03 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 2a 90 00 } //01 00 
		$a_01_2 = {4f 00 6c 00 70 00 6a 00 7a 00 66 00 66 00 77 00 6e 00 6f 00 66 00 6f 00 6e 00 74 00 74 00 73 00 6f 00 66 00 62 00 6f 00 } //00 00 
	condition:
		any of ($a_*)
 
}