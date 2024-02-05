
rule TrojanDownloader_Linux_Mirai_H_MTB{
	meta:
		description = "TrojanDownloader:Linux/Mirai.H!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 47 45 54 20 2f 90 02 20 6d 69 70 73 20 48 54 54 50 2f 31 2e 30 0d 0a 90 00 } //01 00 
		$a_03_1 = {8f 85 80 18 8f 99 80 90 01 01 26 70 00 90 01 01 24 a5 90 01 02 02 20 20 21 03 20 f8 09 02 00 30 21 8f bc 00 10 10 50 00 07 00 00 80 21 8f 99 80 90 01 01 00 00 00 00 03 20 f8 09 24 04 00 03 8f bc 00 10 00 00 80 21 8f 99 80 90 01 01 02 20 20 21 27 a5 00 18 03 20 f8 09 24 06 00 01 8f bc 00 10 24 03 00 01 8f 99 80 90 01 01 10 43 00 04 24 04 00 04 03 20 f8 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}