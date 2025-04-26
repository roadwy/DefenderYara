
rule TrojanDownloader_O97M_Powdow_SYU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SYU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 4f 70 65 6e 20 22 67 65 74 22 2c 20 22 68 74 74 70 73 3a 2f 2f 61 64 66 68 6a 69 75 79 71 6e 6d 61 68 64 66 69 75 61 64 2e 63 6f 6d 2f 69 6e 64 65 78 2e 70 68 70 22 2c 20 46 61 6c 73 65 } //1 .Open "get", "https://adfhjiuyqnmahdfiuad.com/index.php", False
		$a_01_1 = {44 6f 63 75 6d 65 6e 74 2e 4c 6f 61 64 58 4d 4c 20 64 4f 63 75 4d 65 4e 74 58 4d 6c 2e 72 65 73 70 6f 6e 73 65 54 65 78 74 } //1 Document.LoadXML dOcuMeNtXMl.responseText
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}