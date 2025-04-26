
rule TrojanDownloader_O97M_Powdow_SA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6d 61 72 69 6e 67 61 72 65 73 65 72 76 61 73 2e 63 6f 6d 2e 62 72 2f } //1 http://maringareservas.com.br/
		$a_03_1 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 24 28 22 43 4f 4d 53 50 45 43 22 29 20 26 [0-79] 6c 6f 63 61 6c 68 6f 73 74 20 26 20 22 20 26 20 50 53 68 65 6c 6c 43 6f 64 65 2c 20 76 62 48 69 64 65 } //1
		$a_01_2 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 } //1 Sub Workbook_Open()
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_SA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 73 64 6d 61 73 69 64 20 3d 20 53 74 72 52 65 76 65 72 73 65 28 53 52 65 76 65 72 73 65 4d 6f 64 28 22 70 2f 2e 6d 40 6a 34 38 30 39 32 33 25 31 34 38 30 39 32 33 2f 31 3a 2f 74 70 68 74 20 22 29 29 } //1 maisdmasid = StrReverse(SReverseMod("p/.m@j480923%1480923/1:/tpht "))
		$a_01_1 = {6b 61 6b 73 6d 64 39 61 73 64 6d 20 3d 20 } //1 kaksmd9asdm = 
		$a_01_2 = {78 6d 6f 72 67 61 6e 64 64 20 3d 20 53 74 72 52 65 76 65 72 73 65 28 53 52 65 76 65 72 73 65 4d 6f 64 28 22 6e 67 70 69 22 29 29 } //1 xmorgandd = StrReverse(SReverseMod("ngpi"))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}