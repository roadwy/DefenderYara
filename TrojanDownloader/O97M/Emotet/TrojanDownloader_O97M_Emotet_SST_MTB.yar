
rule TrojanDownloader_O97M_Emotet_SST_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SST!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6a 61 6e 73 68 61 62 64 2e 63 6f 6d 2f 45 33 33 5a 46 76 2f } //1 http://janshabd.com/E33ZFv/
		$a_01_1 = {68 74 74 70 3a 2f 2f 61 6d 6f 72 65 73 70 61 73 61 6c 6f 6e 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 5a 73 4b 30 46 62 47 47 4c 71 4e 70 6d 7a 4c 2f } //1 http://amorespasalon.com/wp-admin/ZsK0FbGGLqNpmzL/
		$a_01_2 = {68 74 74 70 3a 2f 2f 76 75 6c 6b 61 6e 76 65 67 61 73 62 6f 6e 75 73 2e 6a 65 75 6e 65 74 65 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 68 41 41 46 4a 51 41 31 42 6d 2f } //1 http://vulkanvegasbonus.jeunete.com/wp-content/hAAFJQA1Bm/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}