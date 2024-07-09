
rule TrojanDownloader_Linux_Mirai_D_MTB{
	meta:
		description = "TrojanDownloader:Linux/Mirai.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 80 99 8f 21 20 20 02 1c 00 a5 27 09 f8 20 03 10 00 06 24 10 00 bc 8f 0f 00 41 04 21 80 40 00 18 80 85 8f 48 80 99 8f ?? 06 a5 24 01 00 04 24 09 f8 20 03 ?? 00 06 24 10 00 bc 8f 00 00 00 00 54 80 99 8f 00 00 00 00 09 f8 20 03 23 20 10 00 10 00 bc 8f 00 00 00 00 18 80 85 8f 48 80 99 8f ?? 00 70 26 ?? 06 a5 24 21 20 20 02 } //1
		$a_03_1 = {47 45 54 20 2f [0-20] 2e 6d 70 73 6c 20 48 54 54 50 2f 31 2e 30 0d 0a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}