
rule TrojanDownloader_BAT_Banload_ABN_MTB{
	meta:
		description = "TrojanDownloader:BAT/Banload.ABN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {26 18 13 0e 2b a6 04 20 c7 95 a4 0b 61 03 61 0a 7e 02 00 00 04 0c 08 74 01 00 00 1b 25 06 93 0b 06 18 58 93 07 61 0b 19 13 0e 2b 80 7e 03 00 00 04 74 02 00 00 1b 07 9a 25 0d } //01 00 
		$a_01_1 = {64 00 69 00 7a 00 69 00 70 00 61 00 6c 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}