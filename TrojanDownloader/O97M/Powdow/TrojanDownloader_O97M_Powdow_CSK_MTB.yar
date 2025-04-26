
rule TrojanDownloader_O97M_Powdow_CSK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.CSK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 73 63 72 69 70 74 2e 22 20 26 20 73 68 65 20 26 20 22 6c 22 29 2e 65 78 65 63 28 70 73 6f 77 65 72 73 73 20 26 20 22 68 65 6c 6c } //1 wscript." & she & "l").exec(psowerss & "hell
		$a_03_1 = {31 38 35 2e 31 31 37 2e 39 31 2e 31 39 39 2f 39 39 2f 43 6b 68 70 75 68 6c 2e 65 78 90 0a 23 00 68 74 74 70 3a 2f 2f } //1
		$a_03_2 = {50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 72 65 61 6c 65 78 65 63 75 74 69 76 65 2e 65 78 22 20 26 20 43 68 72 28 31 30 31 29 29 90 0a 37 00 43 3a 5c 55 73 65 72 73 5c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}