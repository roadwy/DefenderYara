
rule TrojanDownloader_Linux_Mirai_K_MTB{
	meta:
		description = "TrojanDownloader:Linux/Mirai.K!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 00 a2 27 40 00 a2 af 40 00 a3 8f 00 00 00 00 04 00 62 24 40 00 a2 af 21 10 60 00 00 00 42 8c 00 00 00 00 3c 00 a2 af 40 00 a3 8f 00 00 00 00 04 00 62 24 40 00 a2 af 21 10 60 00 00 00 42 8c } //1
		$a_03_1 = {21 28 60 02 21 c8 00 02 09 f8 20 03 80 00 06 24 21 30 40 00 10 00 bc 8f 21 20 80 02 07 ?? ?? ?? 21 28 60 02 21 c8 40 02 09 f8 20 03 00 00 00 00 10 00 bc 8f f2 ?? ?? ?? 21 20 20 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}