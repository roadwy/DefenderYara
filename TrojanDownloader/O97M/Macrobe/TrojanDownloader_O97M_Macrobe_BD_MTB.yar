
rule TrojanDownloader_O97M_Macrobe_BD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Macrobe.BD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {63 76 63 76 69 61 67 65 6e 73 2e 73 73 6c 62 6c 69 6e 64 61 64 6f 2e 63 6f 6d 2f [0-04] 2e (68 74 61|68 74 6d 6c) 22 90 0a 3a 00 76 61 72 30 20 3d 20 22 4d 53 48 54 41 20 68 74 74 70 73 3a 2f 2f } //1
		$a_01_1 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //1 Sub Auto_Open()
		$a_01_2 = {53 68 65 6c 6c 20 28 56 61 72 29 } //1 Shell (Var)
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}