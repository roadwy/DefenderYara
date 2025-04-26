
rule TrojanDownloader_O97M_Obfuse_KC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.KC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 28 22 57 22 20 2b 20 22 53 22 20 2b 20 22 63 22 20 2b 20 22 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 = ("W" + "S" + "c" + "ript.Shell")
		$a_03_1 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 22 22 22 64 27 2a 27 [0-19] 27 2a 27 64 27 2a 27 64 5c 70 27 2a 27 2e 6a 5c 5c 3a 70 74 74 68 22 22 22 22 61 74 68 73 27 2a 27 22 22 22 29 } //1
		$a_03_2 = {3d 20 52 65 70 6c 61 63 65 28 [0-0a] 2c 20 22 27 2a 27 22 2c 20 22 6d 22 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}