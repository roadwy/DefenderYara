
rule TrojanDownloader_O97M_Powdow_BBSO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BBSO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 74 65 78 74 31 28 22 6b 65 79 77 6f 72 64 73 22 29 29 90 0c 02 00 57 69 74 68 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 90 0c 02 00 2e 53 61 76 65 41 73 } //1
		$a_03_1 = {54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 73 20 22 22 2c 20 [0-20] 45 6e 64 20 53 75 62 } //1
		$a_01_2 = {47 65 74 4f 62 6a 65 63 74 28 22 22 2c 20 74 65 78 74 31 28 22 63 61 74 65 67 6f 72 79 22 29 29 2e 65 78 65 63 20 53 74 72 52 65 76 65 72 73 65 28 22 20 72 65 72 6f 6c 70 78 65 5c 73 77 6f 64 6e 69 77 5c 3a 63 22 29 20 2b 20 6c 6f 61 64 50 6f 77 44 6f 6f 72 } //1 GetObject("", text1("category")).exec StrReverse(" rerolpxe\swodniw\:c") + loadPowDoor
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}