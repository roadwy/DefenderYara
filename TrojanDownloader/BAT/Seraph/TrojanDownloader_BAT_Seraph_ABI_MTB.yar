
rule TrojanDownloader_BAT_Seraph_ABI_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.ABI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {1e 5b 6f 30 90 01 02 0a 6f 90 01 03 0a 08 17 6f 90 01 03 0a 07 08 6f 90 01 03 0a 17 73 90 01 03 0a 13 04 11 04 02 16 02 8e 69 6f 90 01 03 0a 11 04 6f 90 01 03 0a de 0c 11 04 2c 07 11 04 6f 90 01 03 0a dc 07 6f 90 01 03 0a 13 05 de 14 90 00 } //03 00 
		$a_03_1 = {09 08 6f 23 90 01 02 0a 08 6f 90 01 03 0a 07 6f 90 01 03 0a 08 6f 90 01 03 0a 13 04 de 0d 90 00 } //01 00 
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}