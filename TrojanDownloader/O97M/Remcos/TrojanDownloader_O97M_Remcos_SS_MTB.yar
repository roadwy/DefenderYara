
rule TrojanDownloader_O97M_Remcos_SS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Remcos.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 90 02 0f 20 3d 20 4d 56 4e 49 44 2e 4f 70 65 6e 54 65 78 74 46 69 6c 65 28 4f 47 6c 71 20 2b 20 22 5c 5a 72 54 53 79 2e 76 62 73 22 2c 20 38 2c 20 54 72 75 65 29 } //1
		$a_01_1 = {44 69 72 28 66 35 66 67 30 65 20 2b 20 22 5c 5a 72 54 53 79 2e 76 62 73 22 29 20 3d 20 22 22 20 54 68 65 6e } //1 Dir(f5fg0e + "\ZrTSy.vbs") = "" Then
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}