
rule TrojanDownloader_BAT_Seraph_CAG_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.CAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {14 0a 2b 11 00 72 90 01 01 00 0f 70 28 90 01 01 00 00 06 0a de 03 26 de 00 06 2c ec 28 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 06 7e 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 2a 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}