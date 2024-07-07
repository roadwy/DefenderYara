
rule TrojanDownloader_BAT_Seraph_CAH_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.CAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a de 03 26 de 00 06 6f 90 01 01 00 00 0a 2c e2 28 90 01 01 00 00 0a 06 16 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 28 90 01 01 00 00 06 7e 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 2a 90 00 } //4
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}