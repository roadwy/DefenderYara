
rule TrojanDownloader_O97M_Obfuse_PNO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PNO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 78 6d 6c 68 74 74 70 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50 22 29 } //1 Set xmlhttp = CreateObject("Microsoft.XMLHTTP")
		$a_01_1 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 75 73 74 6f 6d 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 69 70 61 64 72 22 29 2e 56 61 6c 75 65 } //1 = ActiveDocument.CustomDocumentProperties("ipadr").Value
		$a_03_2 = {3d 20 70 76 47 65 74 46 69 6c 65 28 22 68 74 74 70 3a 2f 2f 22 20 2b 20 [0-08] 20 2b 20 22 2f 65 61 73 79 64 6f 72 65 2f 64 6f 63 75 6d 65 6e 74 2f 63 68 61 6d 70 73 46 75 73 69 6f 6e 2e 68 74 6d 6c 3f 6e 6f 63 61 63 68 65 3d 22 20 26 20 4e 6f 77 29 } //1
		$a_01_3 = {43 61 6c 6c 20 64 69 73 70 6c 61 79 45 72 72 6f 72 28 22 55 54 46 38 5f 44 65 63 6f 64 65 22 2c 20 45 72 72 2e 4e 75 6d 62 65 72 2c 20 45 72 72 2e 44 65 73 63 72 69 70 74 69 6f 6e 29 } //1 Call displayError("UTF8_Decode", Err.Number, Err.Description)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}