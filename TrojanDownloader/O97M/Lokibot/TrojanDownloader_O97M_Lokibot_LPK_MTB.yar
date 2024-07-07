
rule TrojanDownloader_O97M_Lokibot_LPK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Lokibot.LPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 32 30 2e 34 30 2e 39 37 2e 39 34 2f 74 37 62 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f 90 02 1f 2e 62 61 74 22 90 00 } //1
		$a_03_1 = {2e 65 78 65 2e 65 78 65 20 26 26 20 90 02 2f 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}