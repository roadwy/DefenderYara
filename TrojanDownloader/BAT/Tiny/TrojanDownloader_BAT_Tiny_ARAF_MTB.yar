
rule TrojanDownloader_BAT_Tiny_ARAF_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.ARAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {07 09 06 09 1e 5a 1e 6f 90 01 03 0a 18 28 90 01 03 0a 9c 00 09 17 58 0d 09 07 8e 69 17 59 fe 02 16 fe 01 13 04 11 04 90 00 } //02 00 
		$a_01_1 = {5c 4e 6a 72 61 74 5c 6f 62 6a 5c 44 65 62 75 67 5c 4e 6a 72 61 74 2e 70 64 62 } //00 00  \Njrat\obj\Debug\Njrat.pdb
	condition:
		any of ($a_*)
 
}