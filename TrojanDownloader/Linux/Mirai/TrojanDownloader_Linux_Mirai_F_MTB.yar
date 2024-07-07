
rule TrojanDownloader_Linux_Mirai_F_MTB{
	meta:
		description = "TrojanDownloader:Linux/Mirai.F!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 47 45 54 20 2f 90 02 20 70 63 20 48 54 54 50 2f 31 2e 30 0d 0a 90 00 } //1
		$a_03_1 = {3c 80 10 00 38 84 90 01 02 7f 90 01 02 78 7f 90 01 02 78 4b ff fe 90 01 01 7f 83 e8 00 41 9e 00 0c 38 60 00 03 4b ff fd 90 01 01 3b a0 00 00 38 81 00 08 38 a0 00 01 7f 90 01 02 78 4b ff fe 90 01 01 2f 83 00 01 38 60 00 04 41 9e 00 08 4b ff fd 90 01 01 89 61 00 08 57 a9 40 2e 3c 00 0d 0a 7d 3d 5b 78 60 00 0d 0a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}