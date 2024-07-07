
rule TrojanDownloader_O97M_Powdow_KO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.KO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {73 74 72 55 52 4c 20 3d 20 22 68 74 74 70 73 3a 2f 2f 31 30 37 2e 31 37 35 2e 33 2e 31 30 2f 55 73 65 72 73 2f 53 65 72 65 6e 65 5f 4d 69 6e 64 73 5f 32 30 32 34 90 04 0d 03 30 2d 39 2e 65 78 65 22 90 00 } //1
		$a_01_1 = {6f 62 6a 48 54 54 50 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 73 74 72 55 52 4c 2c 20 46 61 6c 73 65 } //1 objHTTP.Open "GET", strURL, False
		$a_01_2 = {57 69 74 68 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 44 4f 44 42 2e 53 74 72 65 61 6d 22 29 } //1 With CreateObject("ADODB.Stream")
		$a_01_3 = {43 61 6c 6c 20 53 68 65 6c 6c 28 73 74 72 46 69 6c 65 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 29 } //1 Call Shell(strFile, vbNormalFocus)
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}