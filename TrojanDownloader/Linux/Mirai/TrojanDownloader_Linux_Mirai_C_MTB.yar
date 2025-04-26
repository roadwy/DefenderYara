
rule TrojanDownloader_Linux_Mirai_C_MTB{
	meta:
		description = "TrojanDownloader:Linux/Mirai.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 4d 49 52 41 49 0a 00 [0-15] 4e 49 46 0a 00 [0-05] 47 45 54 20 2f [0-20] 20 48 54 54 50 2f 31 2e 30 0d 0a 0d 0a 00 [0-20] 46 49 4e 0a 00 } //1
		$a_03_1 = {00 4e 49 46 0a 00 [0-08] 47 45 54 20 2f 62 69 6e 73 2f [0-10] 2e [0-08] 20 48 54 54 50 2f 31 2e 30 0d 0a 55 73 65 72 2d 41 67 65 6e 74 3a 20 [0-10] 4d 69 72 61 69 0d 0a [0-10] 00 42 4f 41 54 0a 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}