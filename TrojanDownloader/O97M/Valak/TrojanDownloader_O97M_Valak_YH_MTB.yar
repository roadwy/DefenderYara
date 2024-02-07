
rule TrojanDownloader_O97M_Valak_YH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Valak.YH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 40 6a 2e 6d 70 } //01 00  %909123id%909123id%909123id%909123id%909123id@j.mp
		$a_03_1 = {25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 90 02 30 2e 6d 70 90 00 } //01 00 
		$a_01_2 = {7a 75 6f 6f 73 61 6f 64 20 3d 20 70 79 61 72 20 2b 20 6b 6f 6f 6b 20 2b 20 6b 6f 6f 6b 20 2b 20 74 79 72 69 73 61 62 69 20 2b 20 6f 6b 61 6c 32 73 20 2b 20 6a 61 73 69 6b 6b } //01 00  zuoosaod = pyar + kook + kook + tyrisabi + okal2s + jasikk
		$a_01_3 = {7a 75 6f 6f 73 61 6f 64 20 3d 20 70 79 61 72 31 20 2b 20 6b 6f 6f 6b 31 20 2b 20 6b 6f 6f 6b 31 20 2b 20 74 79 72 69 73 61 62 69 31 20 2b 20 6f 6b 61 6c 32 73 31 20 2b 20 6a 61 73 69 6b 6b 31 } //01 00  zuoosaod = pyar1 + kook1 + kook1 + tyrisabi1 + okal2s1 + jasikk1
		$a_03_4 = {6f 6b 61 6c 32 90 02 03 20 3d 20 22 73 3a 2f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}