
rule TrojanDownloader_O97M_Emotet_RAGG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RAGG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {52 45 54 55 [0-0a] 28 29 [0-0a] 52 4e [0-0a] 65 90 0a 00 9f 22 [0-0a] 3a [0-0a] 3d [0-0a] 2c [0-0a] 5c [0-0a] 43 [0-0a] 41 [0-1f] 4c } //1
		$a_01_1 = {61 75 74 6f 5f 6f 70 65 6e } //-2 auto_open
		$a_01_2 = {43 6f 70 79 72 69 67 68 74 20 31 39 39 35 } //-2 Copyright 1995
		$a_01_3 = {4f 72 64 65 72 } //-2 Order
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*-2+(#a_01_2  & 1)*-2+(#a_01_3  & 1)*-2) >=1
 
}