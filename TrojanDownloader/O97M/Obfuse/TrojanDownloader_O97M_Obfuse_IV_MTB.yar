
rule TrojanDownloader_O97M_Obfuse_IV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.IV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 44 65 66 61 75 6c 74 54 61 72 67 65 74 46 72 61 6d 65 20 26 20 22 6f 6e 2d 73 74 61 62 2e 6f 6e 6c 69 6e 65 2f 72 65 73 75 6c 74 2f 32 37 35 34 2e 6a 70 67 27 } //1 ThisDocument.DefaultTargetFrame & "on-stab.online/result/2754.jpg'
		$a_01_1 = {4c 44 52 5f 32 37 35 34 2e 6a 73 } //1 LDR_2754.js
		$a_01_2 = {3d 20 45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 20 26 20 22 5c 22 } //1 = Environ("APPDATA") & "\"
		$a_01_3 = {53 68 6c 57 61 69 20 73 74 72 36 35 20 26 20 22 66 6f 6c 64 31 5c 22 20 26 20 22 66 69 6c 65 44 6f 77 6e 36 35 36 35 39 33 22 } //1 ShlWai str65 & "fold1\" & "fileDown656593"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}