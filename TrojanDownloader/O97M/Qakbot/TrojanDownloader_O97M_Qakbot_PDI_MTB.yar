
rule TrojanDownloader_O97M_Qakbot_PDI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PDI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 69 6b 65 74 69 63 6b 65 74 73 2e 63 6f 6d 2f 66 44 6a 49 47 67 57 45 51 70 6b 2f 44 6e 76 68 6e 68 4f 2e 70 6e 67 } //1 liketickets.com/fDjIGgWEQpk/DnvhnhO.png
		$a_01_1 = {61 75 74 6f 39 35 2e 6e 65 74 2f 72 6f 44 49 42 52 54 73 58 7a 4a 42 2f 44 6e 76 68 6e 68 4f 2e 70 6e 67 } //1 auto95.net/roDIBRTsXzJB/DnvhnhO.png
		$a_01_2 = {63 61 6e 75 2e 6d 6f 62 69 2f 55 5a 58 55 38 31 78 50 2f 44 6e 76 68 6e 68 4f 2e 70 6e 67 } //1 canu.mobi/UZXU81xP/DnvhnhO.png
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}