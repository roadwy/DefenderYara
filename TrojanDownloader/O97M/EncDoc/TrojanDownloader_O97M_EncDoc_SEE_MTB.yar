
rule TrojanDownloader_O97M_EncDoc_SEE_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SEE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 73 78 6d 6c 32 2e 44 4f 4d 44 6f 63 75 6d 65 6e 74 2e 36 2e 30 22 29 } //1 = CreateObject("Msxml2.DOMDocument.6.0")
		$a_01_2 = {2e 4c 6f 61 64 58 4d 4c 20 28 4c 6f 61 64 58 4d 4c 28 22 3c 3f 6b 7a 79 20 69 72 65 66 76 62 61 3d 27 31 2e 30 27 3f 3e 20 3c 66 67 6c 79 72 66 75 72 72 67 20 6b 7a 79 61 66 3d 22 22 75 67 67 63 3a 2f 2f 6a 6a 6a 2e 6a 33 2e 62 65 74 2f 31 39 39 39 2f 4b 46 59 2f 47 65 6e 61 66 73 62 65 7a 22 22 20 6b 7a 79 61 66 3a 7a 66 3d 22 22 68 65 61 3a 66 70 75 72 7a 6e 66 2d 7a 76 70 65 62 66 62 73 67 2d 70 62 7a 3a 6b 66 79 67 22 22 20 6b 7a 79 61 66 3a 68 66 72 65 3d 22 22 63 79 6e 70 72 75 62 79 71 72 65 22 22 20 69 72 65 66 76 62 61 3d 22 22 31 2e 30 22 22 3e } //1 .LoadXML (LoadXML("<?kzy irefvba='1.0'?> <fglyrfurrg kzyaf=""uggc://jjj.j3.bet/1999/KFY/Genafsbez"" kzyaf:zf=""hea:fpurznf-zvpebfbsg-pbz:kfyg"" kzyaf:hfre=""cynprubyqre"" irefvba=""1.0"">
		$a_01_3 = {74 65 73 74 2e 73 65 74 50 72 6f 70 65 72 74 79 20 22 41 6c 6c 6f 77 58 73 6c 74 53 63 72 69 70 74 22 2c 20 54 72 75 65 } //1 test.setProperty "AllowXsltScript", True
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}