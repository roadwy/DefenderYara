
rule TrojanDownloader_Linux_Mirai_G_MTB{
	meta:
		description = "TrojanDownloader:Linux/Mirai.G!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 47 45 54 20 2f [0-10] 2f [0-10] 73 68 34 20 48 54 54 50 2f 31 2e 30 } //1
		$a_03_1 = {d5 0b 40 83 66 80 30 02 89 ?? d1 0b 41 03 e4 00 e8 ?? 9a 93 64 ?? d0 01 e6 ec 3a a3 65 0b 40 18 48 01 88 03 8d 04 e4 ?? d1 0b 41 09 00 a0 61 1b 28 ?? d1 10 38 ec 8b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}